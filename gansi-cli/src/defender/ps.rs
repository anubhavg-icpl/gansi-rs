use std::process::Command;

use anyhow::{anyhow, bail, Context};
use serde_json::Value;

/// Run a PowerShell expression that returns an object; deserialize as JSON.
pub fn get_json(expression: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $ProgressPreference='SilentlyContinue'; \
         Import-Module Defender -ErrorAction Stop; \
         $__r = ({expression}); \
         if ($null -eq $__r) {{ 'null' }} else {{ $__r | ConvertTo-Json -Depth 8 -Compress }}"
    );
    let out = run_powershell(&script)?;
    let trimmed = out.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Value::Null);
    }
    let v: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("invalid JSON from Defender cmdlet: {trimmed}"))?;
    Ok(v)
}

/// Run a PowerShell command for side effects (no required JSON).
pub fn run_ok(expression: &str) -> Result<(), Box<dyn std::error::Error>> {
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $ProgressPreference='SilentlyContinue'; \
         Import-Module Defender -ErrorAction Stop; \
         {expression} | Out-Null; \
         'OK'"
    );
    let out = run_powershell(&script)?;
    if !out.contains("OK") {
        bail!("unexpected PowerShell output: {out}");
    }
    Ok(())
}

fn run_powershell(script: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Prefer Windows PowerShell 5.1 path; fall back to `powershell` on PATH.
    let candidates = [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe",
        "powershell",
    ];

    let mut last_err = None;
    for exe in candidates {
        let output = Command::new(exe)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if out.status.success() {
                    return Ok(stdout);
                }
                let msg = format!(
                    "PowerShell failed ({exe}): {}\n{stderr}\n{stdout}",
                    out.status
                );
                last_err = Some(anyhow!(msg));
            },
            Err(e) => {
                last_err = Some(anyhow!("failed to spawn {exe}: {e}"));
            },
        }
    }

    Err(last_err
        .unwrap_or_else(|| anyhow!("PowerShell not available"))
        .into())
}

/// Single-quote a string for PowerShell (escape embedded quotes).
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// PowerShell string array literal: @('a','b')
pub fn ps_string_array(items: &[String]) -> String {
    if items.is_empty() {
        return "@()".into();
    }
    let inner = items
        .iter()
        .map(|s| ps_quote(s))
        .collect::<Vec<_>>()
        .join(",");
    format!("@({inner})")
}
