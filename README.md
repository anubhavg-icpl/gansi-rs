# gansi-rs

**Gansi** (Gain + AMSI) is a Windows AMSI COM provider and CLI written in Rust by [Anubhav Gain](https://github.com/anubhavg-icpl).

It registers as an `IAntimalwareProvider2` implementation, heuristically inspects PowerShell (and embedded C#) content, and streams findings to a named pipe for local tracing.

> Research / defensive monitoring tool. Requires Windows and administrator rights for COM + AMSI provider registration.

## Workspace

| Crate | Role |
|-------|------|
| `gansi-com` | AMSI COM provider (`gansi_com.dll`) |
| `gansi-cli` | Register / unregister / trace events |
| `shared` | Pipe protocol, `FfiString`, constants |
| `macros` | Compile-time keyword + SHA256 PHF helpers |
| `xtask` | Release packaging (`cargo xtask dist`) |

## Requirements

- Windows (x64)
- Rust stable (edition 2024 toolchain)
- Administrator shell for registration

## Build

```powershell
cargo build --release -p gansi-com -p gansi-cli
# or
cargo xtask dist
```

Artifacts land under `target\release\` (or `dist\` via xtask):

- `gansi_com.dll`
- `gansi-cli.exe`

## Usage

```powershell
# Register COM + AMSI provider (admin)
gansi-cli.exe --register [path\to\gansi_com.dll] [pipe_suffix]

# Trace events only (provider already registered)
gansi-cli.exe --trace [path\to\gansi_com.dll] [pipe_suffix]

# Register and trace in one process
gansi-cli.exe --all [path\to\gansi_com.dll] [pipe_suffix]

# Unregister
gansi-cli.exe --unregister [path\to\gansi_com.dll]
```

Defaults:

- DLL: `gansi_com.dll` (must be loadable from cwd/`PATH`)
- Pipe: `\\.\pipe\gansi`

## Architecture (brief)

1. CLI loads the DLL and calls `DllRegisterServerWithPipe`.
2. Provider writes HKLM CLSID + `AMSI\Providers` keys.
3. AMSI loads the provider; `Scan` runs SHA cleanlist + PS/C# heuristics.
4. Detected / suspicious scripts are reported as length-prefixed JSON over the named pipe.
5. CLI `--trace` / `--all` prints `GansiMessage` events.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Anubhav Gain** — [@anubhavg-icpl](https://github.com/anubhavg-icpl)
