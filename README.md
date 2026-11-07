# volsyms

Automate **Volatility 3** Linux/macOS kernel-symbol (ISF) acquisition.

Analysing a Linux or macOS memory image with Volatility 3 needs a matching
Intermediate Symbol File (ISF) for that exact kernel build. `volsyms` gets you
one of two ways:

- **`find`** — carve the kernel banner from a memory dump, look it up in the
  [`Abyss-W4tcher/volatility3-symbols`](https://github.com/Abyss-W4tcher/volatility3-symbols)
  index, download the matching ISF, and drop it into Volatility 3's symbols
  directory. The 30 GB repo is never cloned — only the one file is downloaded.
- **`build`** — generate an ISF locally with
  [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json) from a
  `vmlinux` carrying DWARF debug info and/or a `System.map`.

Pure standard library. No dependencies beyond Python 3 (and Go, only if you let
it build `dwarf2json` for you).

## Usage

> Run it with the **same Python as your Volatility 3** so it installs into the
> right `symbols/` directory — e.g. `~/.venv/bin/python volsyms.py …`, or pass
> `--symbols-dir` explicitly.

```sh
# Just show the banner(s) in a dump
volsyms banner -f memory.lime

# Find, download and install the matching ISF
volsyms find -f memory.lime

# See what it would download, without touching anything
volsyms find -f memory.lime --dry-run

# Look up a banner string directly (no dump needed)
volsyms find --banner 'Linux version 5.4.0-42-generic ...'

# Search the cached index for available banners (no dump needed)
volsyms search '5.4.0-42-generic'

# Print the version
volsyms --version

# Build an ISF from a DWARF kernel with dwarf2json (builds the tool if needed)
volsyms build --elf ./vmlinux --system-map ./System.map --install --build-tool

# Build an ISF from BTF with btf2json (no DWARF needed) and let it load
volsyms build --btf ./vmlinux --system-map ./System.map --install --build-tool --patch-schema
```

### Handy alias

```sh
alias volsyms='~/.venv/bin/python ~/vol3-tools/volsyms.py'
```

## Building a profile from scratch (Arch Linux)

When the online index has no match, build the ISF yourself. There are two
generators; `volsyms build` drives either and can install the toolchain for you.

| Generator | Needs | When to use |
|---|---|---|
| `dwarf2json` | a `vmlinux` **with DWARF** debug info | you compiled the kernel with `CONFIG_DEBUG_INFO=y`, or have a debug kernel |
| `btf2json` | a kernel with **BTF** + a symbol map | the usual Arch case: the stock kernel ships BTF (`CONFIG_DEBUG_INFO_BTF=y`) but no DWARF |

Install the toolchain (Arch):

```sh
sudo pacman -S --needed go rust dwarves   # go: dwarf2json, rust: btf2json, dwarves: pahole
```

### From a stock Arch kernel (BTF path)

`/boot/vmlinuz-linux` is stripped (no DWARF) but carries BTF, so use `btf2json`:

```sh
# 1. extract the vmlinux (with its .BTF section) from the boot image
/usr/src/linux/scripts/extract-vmlinux /boot/vmlinuz-linux > /tmp/vmlinux

# 2. symbol addresses — kallsyms is a live System.map (root, else addresses are 0)
sudo sh -c 'cat /proc/kallsyms > /tmp/System.map'

# 3. build, install into the symbols dir, and patch the schema so it loads
~/.venv/bin/python volsyms.py build \
    --btf /tmp/vmlinux --system-map /tmp/System.map \
    --install --build-tool --patch-schema
```

> `btf2json` profiles declare `kind: btf`, which Volatility's JSON schema rejects
> until patched — `--patch-schema` does that one-off edit to your install.

### From a kernel you compiled with debug info (DWARF path)

```sh
# vmlinux is in the kernel build tree root when CONFIG_DEBUG_INFO=y
~/.venv/bin/python volsyms.py build \
    --elf /path/to/linux/vmlinux --system-map /path/to/linux/System.map \
    --install --build-tool
```

> Other distros: a DWARF `vmlinux` comes from that distro's debug-kernel package
> (e.g. Fedora `kernel-debuginfo`). The commands above are for an Arch host.

## How `find` works

1. Carves every `Linux version …` / `Darwin Kernel Version …` string from the
   dump (memory-mapped, fast).
2. Fetches and caches the project's stable `banners/banners_plain.json` index
   (`~/.cache/volsyms/`, refreshed weekly).
3. Matches your banner (exact → whitespace-normalised → fuzzy ≥ 0.9).
4. Downloads the matching `.json.xz` ISF into Volatility 3's symbols directory.
   The filename and subdirectory are cosmetic — Volatility indexes ISFs by the
   banner inside the file, so it resolves regardless of Linux/macOS subfolder.

If no match exists, build one with `volsyms build`.

## Notes

- ISFs are served from GitHub Release assets; behind a firewall, allow
  `release-assets.githubusercontent.com`.
- After installing, if Volatility already cached the kernel as "unknown", run it
  once with `--clear-cache`.
- macOS dumps work the same way through the same index.

## Credits

ISF collection and banner index by
[Abyss-W4tcher](https://github.com/Abyss-W4tcher/volatility3-symbols).
Symbol generation by the Volatility Foundation's `dwarf2json`.

## License

[MIT](LICENSE)
