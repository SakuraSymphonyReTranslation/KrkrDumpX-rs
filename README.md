# KrkrDumpX-rs

Static Kirikiri XP3 / Cxdec Hxv4 key extractor, archive analyzer, auto-unhasher, and extractor written in Rust.

It reads keys directly from the game `.exe`, decrypts XP3/Hxv4 archives, and recovers hashed filenames from internal game data without launching the game or requiring an external `HxNames.lst`.

## How it works

1. Locate the game `.exe` (checks PE resources `RCDATA/STARTUP.TJS`, `RCDATA/BOOTSTRAP`, and `TEXT/127`).
2. Extract the 8192-byte `bres` salt, decrypt `STARTUP.TJS` (SHA3-384 + ChaCha8), trace `_bootStrap(...)` in TJS2 bytecode, unpack `bootstrap.dll`, read its config table, and derive `FilterManager` / `DripValue` state in-process (32-bit x86).
3. Parse XP3 headers (standard and `0x17 -> 0x20` custom), decrypt the Hxv4 table (XChaCha20-Poly1305), derive per-entry 48-byte filter states, verify Adler32, and classify file headers.
4. Decrypt streams and run multi-round unhashing against PSB/MDF, TJS2100 bytecode, `TJS/4s0` and `TJS/ns0` PBD, PSD layer tables, `.stand`, `.sinfo`, `base.stage`, `storages.tjs`, `sysse.ini`, CSV/INI tables, and numeric sequences.

## Build

The project defaults to `i686-pc-windows-msvc` (see `.cargo/config.toml`) so it can load 32-bit `bootstrap.dll` directly in-process, with `/LARGEADDRESSAWARE` enabled.

```powershell
rustup target add i686-pc-windows-msvc
cargo build --release
```

Output binary: `target\i686-pc-windows-msvc\release\krkrdumpx-rs.exe`

## Usage

### Extract everything (`run`)

```powershell
# Point at a game directory or game .exe
krkrdumpx-rs run "D:\Games\TargetGame" -o "D:\Games\TargetGame\extracted"

# Specific archive, descramble Kirikiri UTF-16LE text, and write HxCryptTool key files
krkrdumpx-rs run "D:\Games\TargetGame" --xp3 "D:\Games\TargetGame\scn.xp3" -o out --descramble --dump-keys
```

### Extract keys only (`keys`)

Writes `drip_program.json`, `static_recover.summary.json`, `bres_salt.bin`, `bootstrap.dll`, and binary key files (`key.bin`, `nonce0.bin`, `nonce1.bin`, `nonce.bin`, `hash_key.bin`, `CxdecTable.bin`, `CxdecOrder.bin`, `keys_info.txt`):

```powershell
krkrdumpx-rs keys "D:\Games\TargetGame" -o "D:\Games\TargetGame\keys"
```

### Analyze and verify archives (`analyze`)

```powershell
krkrdumpx-rs analyze "D:\Games\TargetGame\scn.xp3" --verify --max-entries 20
krkrdumpx-rs analyze "D:\Games\TargetGame\scn.xp3" --drip-program drip_program.json --verify
```

### Extract archives (`extract`)

```powershell
krkrdumpx-rs extract "D:\Games\TargetGame\data.xp3" "D:\Games\TargetGame\scn.xp3" -o out
krkrdumpx-rs extract "D:\Games\TargetGame" -o out --export-lst HxNames.lst
krkrdumpx-rs extract "D:\Games\TargetGame\scn.xp3" -o out --no-unhash
```

### Unhash an already-extracted directory (`unhash`)

```powershell
krkrdumpx-rs unhash "D:\ExtractedGame" --export-lst HxNames.lst
krkrdumpx-rs unhash "D:\ExtractedGame" --dry-run
```

### Compute Hxv4 hashes (`hash`)

```powershell
krkrdumpx-rs hash --path "" --path "data/main/" --file "cglist.csv" --file "startup.tjs"
```

## Overrides

- `--exe <PATH>`: set the game `.exe` explicitly
- `--drip-program <JSON>`: reuse an existing `drip_program.json`
- `--salt-file <BIN>` / `--salt-rva <HEX>` / `--salt-file-offset <HEX>`: override the 8192-byte `bres` salt location
- `--table-rva <HEX>`: override the `bootstrap.dll` config table RVA
- `--bootstrap-zlib-offset <N>`: override the zlib offset in `BOOTSTRAP` (default `8`, auto-probed on failure)
- `--bootstrap-prefix <TEXT>`: override the `_bootStrap(...)` prefix string
- `--archive-seed-hex <HEX>`: override the 8-byte archive seed
- `--force-open-flag <0|1>`: force Hxv4 `open_flag`
- `--names <FILE>`: merge an extra wordlist or `HxNames.lst`
- `--keyed-hash`: use keyed SipHash/BLAKE2s with the derived `hash_key`

## Credits

This project builds on research and code from the following open-source tools:

- [KrkrDump](https://github.com/MLChinoo/KrkrDump-Hasher) (original by crskycode) and [KrkrDump-Mod / KrkrDumpX](https://github.com/alyappy/KrkrDump-Mod)
- [cxdec-hxv4-static-analysis](https://github.com/hktkqj/cxdec-hxv4-static-analysis): static `bres`/BOOTSTRAP/Hxv4/FilterManager derivation
- [hxv4_unhash_tools](https://github.com/MLChinoo/hxv4_unhash_tools) and [hxv4_deobf_tools](https://github.com/MLChinoo/hxv4_deobf_tools): content-driven Hxv4 filename recovery
- [msg-tool](https://github.com/lifegpc/msg-tool): `TJS/4s0` and `TJS/ns0` PackinOne binary decoding reference
- [FreeMote](https://github.com/UlyssesWu/FreeMote) and GARbro contributors for PSB and Kirikiri format documentation

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
