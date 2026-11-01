#!/usr/bin/env python3
# volsyms - automate Linux/macOS ISF kernel-symbol acquisition for Volatility 3.
#
# Two modes:
#   find   Carve the kernel banner from a memory dump, look it up in the
#          Abyss-W4tcher/volatility3-symbols index, download the matching ISF
#          and drop it into Volatility 3's symbols directory.
#   build  Generate an ISF locally with dwarf2json from a vmlinux-with-DWARF
#          (and/or a System.map), then install it.
#
# Stdlib only. The remote index used is the project's own stable mapping file:
#   https://github.com/Abyss-W4tcher/volatility3-symbols -> banners/banners_plain.json
# which maps a full "Linux version ..." banner to a list of ISF (.json.xz) URLs.

import argparse
import difflib
import json
import lzma
import mmap
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

BANNERS_PLAIN_URL = (
    "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners_plain.json"
)
CACHE_DIR = os.path.expanduser("~/.cache/volsyms")
CACHE_FILE = os.path.join(CACHE_DIR, "banners_plain.json")
CACHE_MAX_AGE = 7 * 24 * 3600  # refresh the index weekly
BANNER_RE = re.compile(rb"Linux version \d+\.\d+[^\x00\n]{0,400}")
DWARF2JSON_REPO = "github.com/volatilityfoundation/dwarf2json@latest"
BTF2JSON_REPO = "https://github.com/vobst/btf2json"


def log(msg):
    print(f"[volsyms] {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Banner carving
# --------------------------------------------------------------------------- #
def carve_banners(dump_path):
    """Return the unique 'Linux version ...' banners found in a dump."""
    seen, out = set(), []
    with open(dump_path, "rb") as fh:
        try:
            buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            # Empty file or mmap unsupported: fall back to a chunked scan.
            return _carve_chunked(fh)
        try:
            for m in BANNER_RE.finditer(buf):
                b = m.group().split(b"\x00", 1)[0].rstrip()
                try:
                    s = b.decode("ascii")
                except UnicodeDecodeError:
                    continue
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        finally:
            buf.close()
    return out


def _carve_chunked(fh, chunk=64 << 20, overlap=512):
    seen, out, tail = set(), [], b""
    fh.seek(0)
    while True:
        data = fh.read(chunk)
        if not data:
            break
        for m in BANNER_RE.finditer(tail + data):
            b = m.group().split(b"\x00", 1)[0].rstrip()
            try:
                s = b.decode("ascii")
            except UnicodeDecodeError:
                continue
            if s not in seen:
                seen.add(s)
                out.append(s)
        tail = data[-overlap:]
    return out


# --------------------------------------------------------------------------- #
# Remote index
# --------------------------------------------------------------------------- #
def load_index(refresh=False):
    """Download (and cache) the banner->ISF-URL mapping, returning a dict."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    fresh = (
        os.path.exists(CACHE_FILE)
        and (time.time() - os.path.getmtime(CACHE_FILE)) < CACHE_MAX_AGE
    )
    if refresh or not fresh:
        log(f"fetching index: {BANNERS_PLAIN_URL}")
        try:
            with urllib.request.urlopen(BANNERS_PLAIN_URL, timeout=60) as r:
                data = r.read()
            with open(CACHE_FILE, "wb") as out:
                out.write(data)
        except Exception as e:
            if os.path.exists(CACHE_FILE):
                log(f"fetch failed ({e}); using cached copy")
            else:
                raise SystemExit(f"[volsyms] could not fetch index and no cache: {e}")
    with open(CACHE_FILE, "rb") as fh:
        return json.load(fh)


def match_banner(banner, index, fuzzy=True):
    """Return (matched_key, urls). Try exact, whitespace-normalised, then fuzzy."""
    if banner in index:
        return banner, index[banner]
    norm = {re.sub(r"\s+", " ", k).strip(): k for k in index}
    key = re.sub(r"\s+", " ", banner).strip()
    if key in norm:
        orig = norm[key]
        return orig, index[orig]
    if fuzzy:
        close = difflib.get_close_matches(key, list(norm), n=1, cutoff=0.9)
        if close:
            orig = norm[close[0]]
            return orig, index[orig]
    return None, None


# --------------------------------------------------------------------------- #
# Symbols directory + install
# --------------------------------------------------------------------------- #
def default_symbols_dir():
    try:
        import volatility3

        base = os.path.dirname(volatility3.__file__)
        return os.path.join(base, "symbols", "linux")
    except Exception:
        return None


def install_isf(url, symbols_dir, dry_run=False):
    name = urllib.parse.unquote(os.path.basename(urllib.parse.urlparse(url).path))
    dest = os.path.join(symbols_dir, name)
    if dry_run:
        log(f"[dry-run] would download {url}")
        log(f"[dry-run] would install {dest}")
        return dest
    os.makedirs(symbols_dir, exist_ok=True)
    log(f"downloading {url}")
    tmp = dest + ".part"
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as out:
        shutil.copyfileobj(r, out)
    os.replace(tmp, dest)
    log(f"installed {dest} ({os.path.getsize(dest)} bytes)")
    return dest


# --------------------------------------------------------------------------- #
# dwarf2json
# --------------------------------------------------------------------------- #
def ensure_dwarf2json(build=False):
    exe = shutil.which("dwarf2json")
    if exe:
        return exe
    gobin = os.path.join(
        os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin", "dwarf2json"
    )
    if os.path.exists(gobin):
        return gobin
    if not build:
        return None
    if not shutil.which("go"):
        raise SystemExit("[volsyms] 'go' not found; cannot build dwarf2json")
    log(f"building dwarf2json via: go install {DWARF2JSON_REPO}")
    subprocess.run(["go", "install", DWARF2JSON_REPO], check=True)
    return gobin if os.path.exists(gobin) else shutil.which("dwarf2json")


def build_isf(elf, system_map, out_path, build_tool=False):
    exe = ensure_dwarf2json(build=build_tool)
    if not exe:
        raise SystemExit(
            "[volsyms] dwarf2json not found. Re-run with --build-tool (needs Go)."
        )
    cmd = [exe, "linux"]
    if elf:
        cmd += ["--elf", elf]
    if system_map:
        cmd += ["--system-map", system_map]
    log("running: " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.buffer.write(proc.stderr)
        raise SystemExit(f"[volsyms] dwarf2json failed (exit {proc.returncode})")
    _write_out(proc.stdout, out_path)
    return out_path


def _write_out(data, out_path):
    opener = lzma.open if out_path.endswith(".xz") else open
    with opener(out_path, "wb") as fh:
        fh.write(data)
    log(f"wrote {out_path} ({os.path.getsize(out_path)} bytes)")


# --------------------------------------------------------------------------- #
# btf2json (BTF path: build a profile from a kernel with no DWARF, e.g. Arch)
# --------------------------------------------------------------------------- #
def ensure_btf2json(build=False):
    exe = shutil.which("btf2json")
    if exe:
        return exe
    cargobin = os.path.expanduser("~/.cargo/bin/btf2json")
    if os.path.exists(cargobin):
        return cargobin
    if not build:
        return None
    if not shutil.which("cargo"):
        raise SystemExit("[volsyms] 'cargo' not found. On Arch: sudo pacman -S rust")
    log(f"building btf2json via: cargo install --git {BTF2JSON_REPO}")
    subprocess.run(["cargo", "install", "--git", BTF2JSON_REPO], check=True)
    return cargobin if os.path.exists(cargobin) else shutil.which("btf2json")


def build_isf_btf(btf, map_file, out_path, build_tool=False):
    if not map_file:
        raise SystemExit(
            "[volsyms] btf2json needs a symbol map: --system-map <System.map or /proc/kallsyms>"
        )
    exe = ensure_btf2json(build=build_tool)
    if not exe:
        raise SystemExit(
            "[volsyms] btf2json not found. Re-run with --build-tool "
            "(needs Rust/cargo: sudo pacman -S rust)."
        )
    cmd = [exe, "--btf", btf, "--map", map_file]
    log("running: " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.buffer.write(proc.stderr)
        raise SystemExit(f"[volsyms] btf2json failed (exit {proc.returncode})")
    _write_out(proc.stdout, out_path)
    return out_path


def schemas_dir():
    import volatility3

    return os.path.join(os.path.dirname(volatility3.__file__), "schemas")


def patch_schema():
    """Let Volatility 3 accept btf2json profiles (kind: btf/symdb). Idempotent."""
    import glob

    old = '"^(dwarf|symtab|system-map)$"'
    new = '"^(btf|symdb|dwarf|symtab|system-map)$"'
    changed = []
    for f in glob.glob(os.path.join(schemas_dir(), "schema-*.json")):
        txt = open(f, encoding="utf-8").read()
        if old in txt:
            open(f, "w", encoding="utf-8").write(txt.replace(old, new))
            changed.append(os.path.basename(f))
    return changed


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_banner(args):
    banners = carve_banners(args.file)
    if not banners:
        log("no Linux banner found (not a Linux dump, or kernel paged out)")
        return 1
    for b in banners:
        print(b)
    return 0


def cmd_find(args):
    if args.banner:
        banners = [args.banner]
    else:
        banners = carve_banners(args.file)
        if not banners:
            log("no Linux banner found in dump; nothing to look up")
            return 1
        log(f"carved {len(banners)} banner(s); using: {banners[0]}")
    index = load_index(refresh=args.refresh)
    log(f"index holds {len(index)} banners")

    symbols_dir = args.symbols_dir or default_symbols_dir()
    if not symbols_dir and not args.dry_run:
        raise SystemExit("[volsyms] could not locate symbols dir; pass --symbols-dir")

    for banner in banners:
        key, urls = match_banner(banner, index, fuzzy=not args.no_fuzzy)
        if not urls:
            continue
        if key != banner:
            log(f"matched (approx) -> {key}")
        for url in urls:
            install_isf(url, symbols_dir, dry_run=args.dry_run)
        log("done. Run vol with --clear-cache once if it was cached as unknown.")
        return 0
    log("no matching ISF in the index. Use 'build' with dwarf2json instead.")
    return 2


def cmd_build(args):
    use_btf = bool(args.btf)
    if not use_btf and not args.elf and not args.system_map:
        raise SystemExit(
            "[volsyms] build needs --elf <vmlinux-with-DWARF> (dwarf2json) "
            "or --btf <vmlinux> --system-map <map> (btf2json, Arch-friendly)"
        )
    src = args.btf or args.elf or args.system_map
    if args.install and not args.out:
        symbols_dir = args.symbols_dir or default_symbols_dir()
        if not symbols_dir:
            raise SystemExit("[volsyms] cannot locate symbols dir; pass --symbols-dir/--out")
        os.makedirs(symbols_dir, exist_ok=True)
        args.out = os.path.join(symbols_dir, os.path.basename(src) + ".json.xz")
    out = args.out or (os.path.basename(src) + ".json.xz")

    if use_btf:
        build_isf_btf(args.btf, args.system_map, out, build_tool=args.build_tool)
        if args.patch_schema:
            ch = patch_schema()
            log(f"schema patched: {', '.join(ch) if ch else '(already allows btf)'}")
        else:
            log(
                "NOTE: Volatility rejects btf2json profiles until its schema is patched. "
                "Re-run with --patch-schema (one-off) or the ISF will not load."
            )
    else:
        build_isf(args.elf, args.system_map, out, build_tool=args.build_tool)
    return 0


def main():
    p = argparse.ArgumentParser(
        description="Automate Volatility 3 Linux/macOS ISF kernel symbols."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("banner", help="print Linux banner(s) carved from a dump")
    pb.add_argument("-f", "--file", required=True)
    pb.set_defaults(func=cmd_banner)

    pf = sub.add_parser("find", help="find+download matching ISF from the online index")
    pf.add_argument("-f", "--file", help="memory dump to carve the banner from")
    pf.add_argument("--banner", help="look up this exact banner instead of carving")
    pf.add_argument("--symbols-dir", help="override Volatility 3 symbols/linux dir")
    pf.add_argument("--refresh", action="store_true", help="force re-download the index")
    pf.add_argument("--no-fuzzy", action="store_true", help="exact matches only")
    pf.add_argument("--dry-run", action="store_true", help="show the URL, do not download")
    pf.set_defaults(func=cmd_find)

    pbuild = sub.add_parser("build", help="build an ISF locally (dwarf2json or btf2json)")
    pbuild.add_argument("--elf", help="vmlinux ELF with DWARF debug info -> dwarf2json")
    pbuild.add_argument(
        "--btf",
        help="vmlinux/BTF source -> btf2json (no DWARF needed; Arch-friendly). "
        "Needs --system-map too.",
    )
    pbuild.add_argument("--system-map", help="System.map or /proc/kallsyms (symbol addresses)")
    pbuild.add_argument("--out", help="output path (.json or .json.xz)")
    pbuild.add_argument("--install", action="store_true", help="write into the symbols dir")
    pbuild.add_argument("--symbols-dir", help="override Volatility 3 symbols/linux dir")
    pbuild.add_argument(
        "--build-tool",
        action="store_true",
        help="build the needed generator if missing (go install / cargo install)",
    )
    pbuild.add_argument(
        "--patch-schema",
        action="store_true",
        help="patch Volatility's schema so btf2json profiles validate",
    )
    pbuild.set_defaults(func=cmd_build)

    args = p.parse_args()
    if args.cmd == "find" and not args.file and not args.banner:
        p.error("find requires -f/--file or --banner")
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
