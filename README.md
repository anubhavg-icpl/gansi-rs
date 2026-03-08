<p align="center">
  <img src="docs/assets/logo-primary.webp" alt="Gansi" width="220" />
</p>

# gansi-rs

**Gansi** (*Gain* + *AMSI*) — Windows AMSI COM provider and CLI in Rust, by [Anubhav Gain](https://github.com/anubhavg-icpl).

Local script telemetry: registers as `IAntimalwareProvider2`, heuristically inspects PowerShell (and embedded C#), streams findings over a named pipe. Optional **Microsoft Defender** management via native WMI (no PowerShell).

> Research / lab tool. Windows x64 + admin for registration. Passive by default (report, don’t block).

[![license](https://img.shields.io/badge/license-MIT-3DDCFF?style=flat-square)](LICENSE)
[![platform](https://img.shields.io/badge/platform-Windows%20x64-8B95A8?style=flat-square)](#requirements)

## Workspace

| Crate | Role |
|-------|------|
| `gansi-com` | AMSI COM provider → `gansi_com.dll` |
| `gansi-cli` | Control plane → `gansi.exe` |
| `shared` | Pipe protocol, `FfiString`, constants |
| `macros` | Compile-time keyword / SHA256 helpers |
| `xtask` | `cargo xtask dist` packaging |

## Requirements

- Windows x64  
- Rust (edition 2024) + MSVC toolchain  
- Administrator for COM / AMSI registration and most Defender preference changes  

## Build

```powershell
cargo build --release -p gansi-com -p gansi-cli
# or
cargo xtask dist   # → dist\gansi_com.dll, dist\gansi.exe
```

## Usage

```powershell
# AMSI provider
gansi register --dll .\gansi_com.dll --pipe gansi
gansi watch    --dll .\gansi_com.dll          # register + live trace; auto-unregister on exit
gansi trace --pipe gansi
gansi unregister --dll .\gansi_com.dll

# Defender (WMI: ROOT\Microsoft\Windows\Defender)
gansi defender health
gansi defender status
gansi defender scan --kind quick
gansi defender update
gansi defender exclude list
gansi defender lab-prep --dir .\dist
```

Aliases: `r` / `u` / `t` / `a` (watch), `def` (defender).  
Defaults: DLL `gansi_com.dll`, pipe `\\.\pipe\gansi`, log `warn` (`--log` / `GANSI_LOG`).

<p align="center">
  <img src="docs/assets/terminal-cli.webp" alt="gansi CLI" width="100%" />
</p>

## How it works

```text
Script host → AMSI → gansi_com.dll (scan + heuristics)
                         ↓ length-prefixed JSON
                   \\.\pipe\gansi → gansi.exe (trace/watch)
```

1. CLI loads the DLL and calls `DllRegisterServerWithPipe`.  
2. Provider writes HKLM CLSID + `AMSI\Providers`.  
3. `Scan`: SHA cleanlist → PS/C# parse (or tokenize) → heuristics → optional pipe report.  
4. Detected/Suspicious: **report**, return `AMSI_RESULT_NOT_DETECTED` (passive).  

Defender commands use `IWbemLocator` / `MSFT_Mp*` classes (same surface as the Defender PowerShell module, without spawning PowerShell).

<p align="center">
  <img src="docs/assets/amsi-diagram.webp" alt="Architecture" width="100%" />
</p>

## Security notes

- Registration and Defender preference changes need **admin**; Tamper Protection / GPO may block changes.  
- Script content may appear on the pipe and in logs — treat as sensitive.  
- Default pipe ACL is lab-friendly; tighten for multi-user hosts.  
- See [SECURITY.md](SECURITY.md).

## Assets

Brand/product stills: [`docs/assets/`](docs/assets/) (WebP).

## License

MIT — [LICENSE](LICENSE)  
**Anubhav Gain** — [@anubhavg-icpl](https://github.com/anubhavg-icpl)
