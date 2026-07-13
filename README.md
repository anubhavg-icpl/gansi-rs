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

### AMSI provider

```powershell
gansi register   --dll .\gansi_com.dll --pipe gansi   # write HKLM CLSID + AMSI\Providers
gansi watch      --dll .\gansi_com.dll                # register + live trace; auto-unregister on Ctrl+C
gansi trace      --pipe gansi                         # listen only (attach to a registered provider)
gansi unregister --dll .\gansi_com.dll                # remove registration
```

### Defender — inspect (read-only)

```powershell
gansi defender health                       # dashboard: protection + signatures + key prefs
gansi defender status  [--json]             # MSFT_MpComputerStatus
gansi defender prefs   [--json]             # MSFT_MpPreference
gansi defender threats [-n 25] [--json]     # detection history (MSFT_MpThreatDetection)
gansi defender catalog [-f EICAR] [-n 20]   # known-threat catalog (MSFT_MpThreatCatalog)
```

### Defender — scan & signatures

```powershell
gansi defender scan --kind quick                  # 1 = Quick
gansi defender scan --kind full                   # 2 = Full
gansi defender scan --kind custom --path C:\dir   # 3 = Custom (requires --path)
gansi defender update                             # MSFT_MpSignature.Update
```

### Defender — exclusions

```powershell
gansi defender exclude list [--json]
gansi defender exclude add    --path C:\lab --extension .ps1 --process foo.exe --ip 10.0.0.1
gansi defender exclude remove --path C:\lab
gansi defender lab-prep --dir .\dist              # exclude gansi.exe / gansi_com.dll for lab use
```

`--path` / `--extension` / `--process` / `--ip` are each repeatable.

### Defender — protection toggles

`status` · `on` · `off` for each (disabling needs admin; Tamper Protection / GPO may block it):

```powershell
gansi defender realtime    status     # real-time protection
gansi defender script-scan on         # AMSI script scanning
gansi defender behavior    off        # behavior monitoring
gansi defender ioav        status     # download / attachment (IOAV) scanning
```

### Defender — preferences & threats (omit the value flag to show current)

```powershell
gansi defender cloud   --maps 2 --block-level 2   # MAPS 0/1/2 · block 0/1/2/4/6 · --show to view
gansi defender cfa     --mode 2                    # controlled folder access: 0 off / 1 on / 2 audit
gansi defender netprot --mode 1                    # network protection:        0 off / 1 on / 2 audit
gansi defender remove-threats                      # MSFT_MpThreat.Remove (admin)
```

Aliases: `r` / `u` / `t` / `a` (watch), `def` (defender); `h` (health), `st` (status), `pref` (prefs), `sig` (update).  
Defaults: DLL `gansi_com.dll`, pipe `\\.\pipe\gansi`, log `warn` (`--log` / `GANSI_LOG`).  
`--json` (on `status` / `prefs` / `threats` / `exclude list`) emits raw JSON — the startup banner currently prints to stdout as well.  
Provider logs land in `C:\gansi\amsi-<pid>-<tid>-<date>.log` (best-effort; skipped if the directory can't be created).

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
