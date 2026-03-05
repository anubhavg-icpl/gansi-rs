mod wmi;

use clap::{Subcommand, ValueEnum};
use serde_json::Value;

use crate::ui;

#[derive(Subcommand, Debug)]
pub enum DefenderCmd {
    /// Health dashboard (status + key preferences)
    #[command(visible_alias = "h")]
    Health,

    /// Microsoft Defender computer status (MSFT_MpComputerStatus)
    #[command(visible_alias = "st")]
    Status {
        /// Emit raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Defender preferences snapshot (MSFT_MpPreference)
    #[command(visible_alias = "pref")]
    Prefs {
        /// Emit raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Start an antivirus scan (MSFT_MpScan.Start)
    Scan {
        /// Scan type
        #[arg(long, short = 't', value_enum, default_value_t = ScanKind::Quick)]
        kind: ScanKind,

        /// Path for custom scan
        #[arg(long, short = 'p', value_name = "PATH")]
        path: Option<String>,
    },

    /// Update antivirus signatures (MSFT_MpSignature.Update)
    #[command(visible_alias = "sig")]
    Update,

    /// Threat detection history (MSFT_MpThreatDetection)
    Threats {
        /// Limit rows after sort (0 = all)
        #[arg(long, short = 'n', default_value_t = 25)]
        limit: usize,

        /// Emit raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Known threat catalog lookup (MSFT_MpThreatCatalog) — optional filter
    Catalog {
        /// Substring filter on ThreatName
        #[arg(long, short = 'f')]
        filter: Option<String>,

        #[arg(long, short = 'n', default_value_t = 20)]
        limit: usize,
    },

    /// Manage path / process / extension exclusions
    #[command(subcommand)]
    Exclude(ExcludeCmd),

    /// Toggle or query real-time protection
    #[command(subcommand)]
    Realtime(ToggleCmd),

    /// Toggle or query script scanning (AMSI-related Defender path)
    #[command(subcommand)]
    ScriptScan(ToggleCmd),

    /// Toggle or query behavior monitoring
    #[command(subcommand)]
    Behavior(ToggleCmd),

    /// Toggle or query IOAV (download/attachment) scanning
    #[command(subcommand)]
    Ioav(ToggleCmd),

    /// Cloud-delivered protection / MAPS reporting level
    Cloud {
        /// 0=Disabled 1=Basic 2=Advanced (MAPSReporting)
        #[arg(long, value_name = "LEVEL")]
        maps: Option<u32>,

        /// Cloud block level: 0 Default, 1 Moderate, 2 High, 4 HighPlus, 6 ZeroTolerance
        #[arg(long, value_name = "LEVEL")]
        block_level: Option<u32>,

        /// Show current cloud-related prefs only
        #[arg(long)]
        show: bool,
    },

    /// Controlled folder access (show or set mode)
    #[command(name = "cfa")]
    ControlledFolderAccess {
        /// 0 Disabled, 1 Enabled, 2 AuditMode
        #[arg(long, value_name = "MODE")]
        mode: Option<u32>,

        #[arg(long)]
        show: bool,
    },

    /// Network protection (show or set)
    #[command(name = "netprot")]
    NetworkProtection {
        /// 0 Disabled, 1 Enabled, 2 AuditMode
        #[arg(long, value_name = "MODE")]
        mode: Option<u32>,

        #[arg(long)]
        show: bool,
    },

    /// Lab helper: exclude Gansi artifacts from Defender scans
    #[command(name = "lab-prep")]
    LabPrep {
        /// Directory containing gansi.exe / gansi_com.dll
        #[arg(long, short = 'd', value_name = "DIR")]
        dir: String,
    },

    /// Remove active threats (MSFT_MpThreat.Remove) — admin
    #[command(name = "remove-threats")]
    RemoveThreats,
}

#[derive(Subcommand, Debug)]
pub enum ExcludeCmd {
    /// List current exclusions
    List {
        #[arg(long)]
        json: bool,
    },
    /// Add exclusion(s)
    Add {
        #[arg(long, value_name = "PATH")]
        path: Vec<String>,
        #[arg(long, value_name = "EXT")]
        extension: Vec<String>,
        #[arg(long, value_name = "PROCESS")]
        process: Vec<String>,
        #[arg(long, value_name = "IP")]
        ip: Vec<String>,
    },
    /// Remove exclusion(s)
    Remove {
        #[arg(long, value_name = "PATH")]
        path: Vec<String>,
        #[arg(long, value_name = "EXT")]
        extension: Vec<String>,
        #[arg(long, value_name = "PROCESS")]
        process: Vec<String>,
        #[arg(long, value_name = "IP")]
        ip: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ToggleCmd {
    /// Show current state
    Status,
    /// Enable the feature
    On,
    /// Disable the feature (may require Tamper Protection off / admin / policy allow)
    Off,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ScanKind {
    Quick,
    Full,
    Custom,
}

pub fn run(cmd: DefenderCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        DefenderCmd::Health => health(),
        DefenderCmd::Status { json } => status(json),
        DefenderCmd::Prefs { json } => prefs(json),
        DefenderCmd::Scan { kind, path } => scan(kind, path.as_deref()),
        DefenderCmd::Update => update_sigs(),
        DefenderCmd::Threats { limit, json } => threats(limit, json),
        DefenderCmd::Catalog { filter, limit } => catalog(filter.as_deref(), limit),
        DefenderCmd::Exclude(c) => exclude(c),
        DefenderCmd::Realtime(t) => toggle_bool(
            "real-time protection",
            "DisableRealtimeMonitoring",
            true,
            t,
        ),
        DefenderCmd::ScriptScan(t) => {
            toggle_bool("script scanning", "DisableScriptScanning", true, t)
        },
        DefenderCmd::Behavior(t) => {
            toggle_bool("behavior monitoring", "DisableBehaviorMonitoring", true, t)
        },
        DefenderCmd::Ioav(t) => toggle_bool("IOAV protection", "DisableIOAVProtection", true, t),
        DefenderCmd::Cloud {
            maps,
            block_level,
            show,
        } => cloud(maps, block_level, show),
        DefenderCmd::ControlledFolderAccess { mode, show } => cfa(mode, show),
        DefenderCmd::NetworkProtection { mode, show } => netprot(mode, show),
        DefenderCmd::LabPrep { dir } => lab_prep(&dir),
        DefenderCmd::RemoveThreats => remove_threats(),
    }
}

fn health() -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · health");
    ui::info("querying Microsoft Defender via WMI (ROOT\\Microsoft\\Windows\\Defender)…");

    let st = wmi::get_status()?;
    let pr = wmi::get_preference()?;

    let enabled = |v: &Value, k: &str| bool_field(v, k).unwrap_or(false);

    ui::section("protection");
    ui::kv("antivirus", on_off(enabled(&st, "AntivirusEnabled")));
    ui::kv("antispyware", on_off(enabled(&st, "AntispywareEnabled")));
    ui::kv(
        "realtime",
        on_off(enabled(&st, "RealTimeProtectionEnabled")),
    );
    ui::kv(
        "on-access",
        on_off(enabled(&st, "OnAccessProtectionEnabled")),
    );
    ui::kv("ioav", on_off(enabled(&st, "IoavProtectionEnabled")));
    ui::kv(
        "behavior",
        on_off(enabled(&st, "BehaviorMonitorEnabled")),
    );
    ui::kv("nis", on_off(enabled(&st, "NISEnabled")));
    ui::kv(
        "tamper",
        on_off(enabled(&st, "IsTamperProtected")),
    );
    ui::kv(
        "mode",
        str_field(&st, "AMRunningMode").unwrap_or_else(|| "?".into()),
    );

    ui::section("signatures");
    ui::kv(
        "av version",
        str_field(&st, "AntivirusSignatureVersion").unwrap_or_default(),
    );
    ui::kv(
        "av age (d)",
        num_field(&st, "AntivirusSignatureAge").unwrap_or_else(|| "?".into()),
    );
    ui::kv(
        "engine",
        str_field(&st, "AMEngineVersion").unwrap_or_default(),
    );
    ui::kv(
        "product",
        str_field(&st, "AMProductVersion").unwrap_or_default(),
    );
    ui::kv(
        "out of date",
        yes_no(enabled(&st, "DefenderSignaturesOutOfDate")),
    );

    ui::section("scans");
    ui::kv(
        "quick overdue",
        yes_no(enabled(&st, "QuickScanOverdue")),
    );
    ui::kv("full overdue", yes_no(enabled(&st, "FullScanOverdue")));
    ui::kv(
        "reboot req",
        yes_no(enabled(&st, "RebootRequired")),
    );

    ui::section("preferences (key)");
    ui::kv(
        "disable RTP",
        yes_no(bool_field(&pr, "DisableRealtimeMonitoring").unwrap_or(false)),
    );
    ui::kv(
        "disable scripts",
        yes_no(bool_field(&pr, "DisableScriptScanning").unwrap_or(false)),
    );
    ui::kv(
        "disable behavior",
        yes_no(bool_field(&pr, "DisableBehaviorMonitoring").unwrap_or(false)),
    );
    ui::kv(
        "MAPS",
        num_field(&pr, "MAPSReporting").unwrap_or_else(|| "?".into()),
    );
    ui::kv(
        "cloud block",
        num_field(&pr, "CloudBlockLevel").unwrap_or_else(|| "?".into()),
    );
    ui::kv(
        "PUA",
        num_field(&pr, "PUAProtection").unwrap_or_else(|| "?".into()),
    );
    ui::kv(
        "excl paths",
        array_len(&pr, "ExclusionPath").to_string(),
    );
    ui::kv(
        "excl procs",
        array_len(&pr, "ExclusionProcess").to_string(),
    );
    ui::kv(
        "excl exts",
        array_len(&pr, "ExclusionExtension").to_string(),
    );

    ui::ok("health snapshot complete");
    ui::info("policy / Tamper Protection may block preference changes");
    println!();
    Ok(())
}

fn status(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · status");
    let v = wmi::get_status()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    print_object_kvs(&v, &[
        "AMProductVersion",
        "AMEngineVersion",
        "AMRunningMode",
        "AMServiceEnabled",
        "AntivirusEnabled",
        "AntispywareEnabled",
        "RealTimeProtectionEnabled",
        "OnAccessProtectionEnabled",
        "IoavProtectionEnabled",
        "BehaviorMonitorEnabled",
        "NISEnabled",
        "IsTamperProtected",
        "TamperProtectionSource",
        "DefenderSignaturesOutOfDate",
        "AntivirusSignatureVersion",
        "AntivirusSignatureAge",
        "AntivirusSignatureLastUpdated",
        "QuickScanAge",
        "FullScanAge",
        "QuickScanOverdue",
        "FullScanOverdue",
        "RebootRequired",
        "ComputerState",
        "IsVirtualMachine",
    ]);
    ui::ok("status loaded");
    println!();
    Ok(())
}

fn prefs(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · preferences");
    let v = wmi::get_preference()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    print_object_kvs(&v, &[
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableScriptScanning",
        "DisableArchiveScanning",
        "DisableEmailScanning",
        "DisableRemovableDriveScanning",
        "DisableScanningNetworkFiles",
        "MAPSReporting",
        "CloudBlockLevel",
        "CloudExtendedTimeout",
        "SubmitSamplesConsent",
        "PUAProtection",
        "EnableNetworkProtection",
        "EnableControlledFolderAccess",
        "ScanAvgCPULoadFactor",
        "SignatureUpdateInterval",
        "ExclusionPath",
        "ExclusionExtension",
        "ExclusionProcess",
        "ExclusionIpAddress",
    ]);
    ui::ok("preferences loaded");
    println!();
    Ok(())
}

fn scan(kind: ScanKind, path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · scan");
    // MSFT_MpScan.Start ScanType: 1 Quick, 2 Full, 3 Custom
    let (scan_type, path_arg) = match kind {
        ScanKind::Quick => {
            ui::kv("type", "Quick (1)");
            (1u8, None)
        },
        ScanKind::Full => {
            ui::kv("type", "Full (2)");
            (2u8, None)
        },
        ScanKind::Custom => {
            let p = path.ok_or("custom scan requires --path")?;
            ui::kv("type", "Custom (3)");
            ui::kv("path", p);
            (3u8, Some(p))
        },
    };
    ui::info("MSFT_MpScan.Start via WMI…");
    wmi::start_scan(scan_type, path_arg)?;
    ui::ok("scan started");
    println!();
    Ok(())
}

fn update_sigs() -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · signature update");
    ui::info("MSFT_MpSignature.Update via WMI…");
    wmi::update_signature()?;
    ui::ok("signature update requested");
    println!();
    Ok(())
}

fn threats(limit: usize, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · threats");
    let v = wmi::get_threat_detections()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let rows = as_array(&v);
    if rows.is_empty() {
        ui::info("no threat detections returned");
        println!();
        return Ok(());
    }
    let take = if limit == 0 {
        rows.len()
    } else {
        limit.min(rows.len())
    };
    for (i, row) in rows.iter().take(take).enumerate() {
        ui::section(&format!("detection {}", i + 1));
        ui::kv(
            "name",
            str_field(row, "ThreatName").unwrap_or_else(|| "?".into()),
        );
        ui::kv(
            "id",
            num_field(row, "ThreatID").unwrap_or_else(|| "?".into()),
        );
        ui::kv(
            "action",
            num_field(row, "ActionSuccess").unwrap_or_else(|| "?".into()),
        );
        ui::kv(
            "resources",
            format!("{}", array_len(row, "Resources")),
        );
        if let Some(t) = str_field(row, "InitialDetectionTime") {
            ui::kv("when", t);
        }
        if let Some(d) = str_field(row, "DomainUser") {
            ui::kv("user", d);
        }
    }
    ui::ok(format!("showing {take} of {} detection(s)", rows.len()));
    println!();
    Ok(())
}

fn catalog(filter: Option<&str>, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · threat catalog");
    let v = wmi::get_threat_catalog(limit, filter)?;
    let rows = as_array(&v);
    if rows.is_empty() {
        ui::info("no catalog rows");
        return Ok(());
    }
    for row in rows.iter().take(limit.max(1)) {
        let id = num_field(row, "ThreatID").unwrap_or_else(|| "?".into());
        let name = str_field(row, "ThreatName").unwrap_or_else(|| "?".into());
        ui::kv(&id, name);
    }
    ui::ok(format!("{} row(s)", rows.len().min(limit.max(1))));
    println!();
    Ok(())
}

fn exclude(cmd: ExcludeCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ExcludeCmd::List { json } => {
            ui::section("defender · exclusions");
            let v = wmi::get_preference()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(());
            }
            print_list_field(&v, "ExclusionPath", "path");
            print_list_field(&v, "ExclusionExtension", "extension");
            print_list_field(&v, "ExclusionProcess", "process");
            print_list_field(&v, "ExclusionIpAddress", "ip");
            ui::ok("exclusions listed");
            println!();
            Ok(())
        },
        ExcludeCmd::Add {
            path,
            extension,
            process,
            ip,
        } => {
            ui::section("defender · exclude add");
            if path.is_empty() && extension.is_empty() && process.is_empty() && ip.is_empty() {
                return Err("specify at least one of --path / --extension / --process / --ip".into());
            }
            let mut args = Vec::new();
            if !path.is_empty() {
                args.push(("ExclusionPath", wmi::WmiArg::StrArray(path)));
            }
            if !extension.is_empty() {
                args.push(("ExclusionExtension", wmi::WmiArg::StrArray(extension)));
            }
            if !process.is_empty() {
                args.push(("ExclusionProcess", wmi::WmiArg::StrArray(process)));
            }
            if !ip.is_empty() {
                args.push(("ExclusionIpAddress", wmi::WmiArg::StrArray(ip)));
            }
            ui::info("MSFT_MpPreference.Add via WMI…");
            wmi::preference_add(&args)?;
            ui::ok("exclusions added (admin + policy permitting)");
            println!();
            Ok(())
        },
        ExcludeCmd::Remove {
            path,
            extension,
            process,
            ip,
        } => {
            ui::section("defender · exclude remove");
            if path.is_empty() && extension.is_empty() && process.is_empty() && ip.is_empty() {
                return Err("specify at least one of --path / --extension / --process / --ip".into());
            }
            let mut args = Vec::new();
            if !path.is_empty() {
                args.push(("ExclusionPath", wmi::WmiArg::StrArray(path)));
            }
            if !extension.is_empty() {
                args.push(("ExclusionExtension", wmi::WmiArg::StrArray(extension)));
            }
            if !process.is_empty() {
                args.push(("ExclusionProcess", wmi::WmiArg::StrArray(process)));
            }
            if !ip.is_empty() {
                args.push(("ExclusionIpAddress", wmi::WmiArg::StrArray(ip)));
            }
            ui::info("MSFT_MpPreference.Remove via WMI…");
            wmi::preference_remove(&args)?;
            ui::ok("exclusions removed (admin + policy permitting)");
            println!();
            Ok(())
        },
    }
}

/// `disable_prop` is the MSFT_MpPreference property that means "feature is off" when true.
fn toggle_bool(
    label: &str,
    disable_prop: &str,
    inverted: bool,
    cmd: ToggleCmd,
) -> Result<(), Box<dyn std::error::Error>> {
    ui::section(&format!("defender · {label}"));
    match cmd {
        ToggleCmd::Status => {
            let v = wmi::get_preference()?;
            let disabled = bool_field(&v, disable_prop).unwrap_or(false);
            let enabled = if inverted { !disabled } else { disabled };
            ui::kv("enabled", on_off(enabled));
            ui::kv(disable_prop, yes_no(disabled));
            if disable_prop == "DisableRealtimeMonitoring" {
                if let Ok(st) = wmi::get_status() {
                    ui::kv(
                        "RTP live",
                        on_off(bool_field(&st, "RealTimeProtectionEnabled").unwrap_or(false)),
                    );
                    ui::kv(
                        "tamper",
                        on_off(bool_field(&st, "IsTamperProtected").unwrap_or(false)),
                    );
                }
            }
            println!();
            Ok(())
        },
        ToggleCmd::On => {
            let disable = if inverted { false } else { true };
            ui::info(format!("MSFT_MpPreference.Set {disable_prop}={disable}"));
            wmi::preference_set(&[(disable_prop, wmi::WmiArg::Bool(disable))])?;
            ui::ok(format!("{label} set to ON (if policy allows)"));
            println!();
            Ok(())
        },
        ToggleCmd::Off => {
            let disable = if inverted { true } else { false };
            ui::warn("disabling protection requires admin; Tamper Protection / GPO may block this");
            ui::info(format!("MSFT_MpPreference.Set {disable_prop}={disable}"));
            wmi::preference_set(&[(disable_prop, wmi::WmiArg::Bool(disable))])?;
            ui::ok(format!("{label} set to OFF (if policy allows)"));
            println!();
            Ok(())
        },
    }
}

fn cloud(
    maps: Option<u32>,
    block_level: Option<u32>,
    show: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · cloud / MAPS");
    if show || (maps.is_none() && block_level.is_none()) {
        let v = wmi::get_preference()?;
        print_object_kvs(&v, &[
            "MAPSReporting",
            "CloudBlockLevel",
            "CloudExtendedTimeout",
            "SubmitSamplesConsent",
        ]);
        ui::info("MAPS: 0=Disabled 1=Basic 2=Advanced");
        ui::info("CloudBlockLevel: 0 Default, 1 Moderate, 2 High, 4 HighPlus, 6 ZeroTolerance");
    }
    let mut args = Vec::new();
    if let Some(m) = maps {
        args.push(("MAPSReporting", wmi::WmiArg::U8(m as u8)));
    }
    if let Some(b) = block_level {
        args.push(("CloudBlockLevel", wmi::WmiArg::U8(b as u8)));
    }
    if !args.is_empty() {
        ui::info("MSFT_MpPreference.Set cloud prefs via WMI…");
        wmi::preference_set(&args)?;
        ui::ok("cloud preferences updated");
    }
    println!();
    Ok(())
}

fn cfa(mode: Option<u32>, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · controlled folder access");
    if show || mode.is_none() {
        let v = wmi::get_preference()?;
        print_object_kvs(&v, &[
            "EnableControlledFolderAccess",
            "ControlledFolderAccessProtectedFolders",
            "ControlledFolderAccessAllowedApplications",
        ]);
        ui::info("mode: 0 Disabled, 1 Enabled, 2 AuditMode");
    }
    if let Some(m) = mode {
        ui::info(format!("MSFT_MpPreference.Set EnableControlledFolderAccess={m}"));
        wmi::preference_set(&[("EnableControlledFolderAccess", wmi::WmiArg::U8(m as u8))])?;
        ui::ok("controlled folder access updated");
    }
    println!();
    Ok(())
}

fn netprot(mode: Option<u32>, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · network protection");
    if show || mode.is_none() {
        let v = wmi::get_preference()?;
        print_object_kvs(&v, &["EnableNetworkProtection"]);
        ui::info("mode: 0 Disabled, 1 Enabled, 2 AuditMode");
    }
    if let Some(m) = mode {
        ui::info(format!("MSFT_MpPreference.Set EnableNetworkProtection={m}"));
        wmi::preference_set(&[("EnableNetworkProtection", wmi::WmiArg::U8(m as u8))])?;
        ui::ok("network protection updated");
    }
    println!();
    Ok(())
}

fn lab_prep(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · lab-prep");
    ui::kv("dir", dir);
    ui::info("MSFT_MpPreference.Add exclusions for Gansi lab artifacts");
    let dll = format!("{dir}\\gansi_com.dll");
    let exe = format!("{dir}\\gansi.exe");
    let paths = vec![dir.to_string(), dll, exe.clone()];
    wmi::preference_add(&[
        ("ExclusionPath", wmi::WmiArg::StrArray(paths)),
        ("ExclusionProcess", wmi::WmiArg::StrArray(vec![exe])),
    ])?;
    ui::ok("lab exclusions applied (admin + policy permitting)");
    ui::warn("remove with: gansi defender exclude remove --path <dir>");
    println!();
    Ok(())
}

fn remove_threats() -> Result<(), Box<dyn std::error::Error>> {
    ui::section("defender · remove threats");
    ui::warn("MSFT_MpThreat.Remove — admin required");
    wmi::remove_threats()?;
    ui::ok("remove threats completed");
    println!();
    Ok(())
}

// --- display helpers ---

fn print_object_kvs(v: &Value, keys: &[&str]) {
    for k in keys {
        let val = match v.get(*k) {
            None | Some(Value::Null) => "-".into(),
            Some(Value::Bool(b)) => on_off(*b),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(a)) => {
                if a.is_empty() {
                    "(empty)".into()
                } else {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            },
            Some(other) => other.to_string(),
        };
        ui::kv(k, val);
    }
}

fn print_list_field(v: &Value, field: &str, label: &str) {
    ui::section(label);
    match v.get(field) {
        Some(Value::Array(a)) if !a.is_empty() => {
            for item in a {
                if let Some(s) = item.as_str() {
                    ui::info(s);
                } else {
                    ui::info(item.to_string());
                }
            }
        },
        Some(Value::String(s)) => ui::info(s),
        _ => ui::info("(none)"),
    }
}

fn as_array(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        other => vec![other.clone()],
    }
}

fn bool_field(v: &Value, k: &str) -> Option<bool> {
    v.get(k).and_then(|x| x.as_bool())
}

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

fn num_field(v: &Value, k: &str) -> Option<String> {
    v.get(k).map(|x| match x {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        _ => x.to_string(),
    })
}

fn array_len(v: &Value, k: &str) -> usize {
    match v.get(k) {
        Some(Value::Array(a)) => a.len(),
        Some(Value::String(_)) => 1,
        _ => 0,
    }
}

fn on_off(v: bool) -> String {
    if v {
        "on".into()
    } else {
        "off".into()
    }
}

fn yes_no(v: bool) -> String {
    if v {
        "yes".into()
    } else {
        "no".into()
    }
}
