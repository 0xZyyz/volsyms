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

# Build an ISF from a debug kernel and install it (builds dwarf2json if needed)
volsyms build --elf ./vmlinux --system-map ./System.map --install --build-tool
```

### Handy alias

```sh
alias volsyms='~/.venv/bin/python ~/vol3-tools/volsyms.py'
```

## How `find` works

1. Carves every `Linux version …` string from the dump (memory-mapped, fast).
2. Fetches and caches the project's stable `banners/banners_plain.json` index
   (`~/.cache/volsyms/`, refreshed weekly).
3. Matches your banner (exact → whitespace-normalised → fuzzy ≥ 0.9).
4. Downloads the matching `.json.xz` ISF into `…/volatility3/symbols/linux/`.
   The filename is cosmetic — Volatility reads the banner inside the file.

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
