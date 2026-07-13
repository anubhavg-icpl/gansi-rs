//! Native Microsoft Defender management via WMI (`IWbemLocator` / `IWbemServices`).
//!
//! Namespace: `ROOT\Microsoft\Windows\Defender`  
//! No PowerShell — uses the same CIM provider the Defender module wraps.

use std::mem::ManuallyDrop;

use anyhow::Context;
use serde_json::{json, Map, Value};
use windows::{
    core::{w, BSTR, PCWSTR},
    Win32::{
        Foundation::{VARIANT_FALSE, VARIANT_TRUE},
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
                CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            },
            Ole::{
                SafeArrayCreateVector, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
                SafeArrayPutElement,
            },
            Variant::{
                VariantClear, VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_ARRAY,
                VT_BOOL, VT_BSTR, VT_DATE, VT_EMPTY, VT_I2, VT_I4, VT_I8, VT_NULL, VT_R8, VT_UI1,
                VT_UI2, VT_UI4, VT_UI8,
            },
            Wmi::{
                IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator,
                WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE,
                WBEM_INFINITE,
            },
        },
    },
};

const DEFENDER_NS: &str = r"ROOT\Microsoft\Windows\Defender";
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;

pub struct DefenderWmi {
    com_owned: bool,
    /// Wrapped in `ManuallyDrop` so the interface is released *before*
    /// `CoUninitialize` in `Drop` — releasing a COM proxy after the apartment
    /// is torn down is an access violation.
    services: ManuallyDrop<IWbemServices>,
}

impl DefenderWmi {
    pub fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let mut com_owned = false;
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            com_owned = true;
        }

        let _ = unsafe {
            CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            )
        };

        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .context("CoCreateInstance(WbemLocator)")?;

        let services = unsafe {
            locator.ConnectServer(
                &BSTR::from(DEFENDER_NS),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
        }
        .with_context(|| {
            format!("ConnectServer({DEFENDER_NS}) — Defender WMI unavailable or access denied")
        })?;

        unsafe {
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
        }
        .context("CoSetProxyBlanket")?;

        Ok(Self {
            com_owned,
            services: ManuallyDrop::new(services),
        })
    }

    pub fn query_class(&self, class: &str) -> Result<Value, Box<dyn std::error::Error>> {
        self.query(&format!("SELECT * FROM {class}"))
    }

    pub fn query(&self, wql: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let enumerator: IEnumWbemClassObject = unsafe {
            self.services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(wql),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
        }
        .with_context(|| format!("ExecQuery: {wql}"))?;

        let mut rows = Vec::new();
        loop {
            let mut slot: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0u32;
            let hr = unsafe { enumerator.Next(WBEM_INFINITE, &mut slot, &mut returned) };
            if returned == 0 {
                break;
            }
            if let Some(obj) = slot[0].take() {
                rows.push(object_to_json(&obj)?);
            }
            if hr.is_err() {
                break;
            }
        }

        Ok(match rows.len() {
            0 => Value::Null,
            1 => rows.pop().unwrap(),
            _ => Value::Array(rows),
        })
    }

    pub fn exec_method(
        &self,
        class: &str,
        method: &str,
        args: &[(&str, WmiArg)],
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut class_obj: Option<IWbemClassObject> = None;
        unsafe {
            self.services.GetObject(
                &BSTR::from(class),
                WBEM_GENERIC_FLAG_TYPE(0),
                None,
                Some(&mut class_obj),
                None,
            )
        }
        .with_context(|| format!("GetObject({class})"))?;
        let class_obj = class_obj.with_context(|| format!("GetObject({class}) returned null"))?;

        let mut in_sig: Option<IWbemClassObject> = None;
        let mut out_sig: Option<IWbemClassObject> = None;
        let method_w = wide(method);
        unsafe {
            class_obj.GetMethod(
                PCWSTR::from_raw(method_w.as_ptr()),
                0,
                &mut in_sig,
                &mut out_sig,
            )
        }
        .with_context(|| format!("GetMethod({class}.{method})"))?;

        let in_params = match in_sig {
            Some(sig) => {
                let inst = unsafe { sig.SpawnInstance(0) }.context("SpawnInstance")?;
                for (name, arg) in args {
                    let mut var = arg.to_variant()?;
                    let name_w = wide(name);
                    let res = unsafe {
                        inst.Put(PCWSTR::from_raw(name_w.as_ptr()), 0, &var, 0)
                    };
                    unsafe {
                        let _ = VariantClear(&mut var);
                    }
                    res.with_context(|| format!("Put({name})"))?;
                }
                Some(inst)
            },
            None => None,
        };

        let mut out: Option<IWbemClassObject> = None;
        unsafe {
            self.services.ExecMethod(
                &BSTR::from(class),
                &BSTR::from(method),
                WBEM_GENERIC_FLAG_TYPE(0),
                None,
                in_params.as_ref(),
                Some(&mut out),
                None,
            )
        }
        .with_context(|| format!("ExecMethod({class}.{method})"))?;

        // Some methods (Set/Add/Remove/Update) may return no out-params object.
        match out {
            Some(o) => object_to_json(&o),
            None => Ok(Value::Null),
        }
    }
}

impl Drop for DefenderWmi {
    fn drop(&mut self) {
        // Release the COM interface first, then uninitialize the apartment.
        // Reversing this order releases a proxy on a torn-down apartment (crash).
        unsafe { ManuallyDrop::drop(&mut self.services) };
        if self.com_owned {
            unsafe { CoUninitialize() };
        }
    }
}

pub enum WmiArg {
    Bool(bool),
    U8(u8),
    Str(String),
    StrArray(Vec<String>),
}

impl WmiArg {
    fn to_variant(&self) -> Result<VARIANT, Box<dyn std::error::Error>> {
        Ok(match self {
            WmiArg::Bool(b) => variant_bool(*b),
            WmiArg::U8(v) => variant_ui1(*v),
            WmiArg::Str(s) => variant_bstr(s),
            WmiArg::StrArray(items) => variant_bstr_array(items)?,
        })
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn variant_bool(v: bool) -> VARIANT {
    let bool_val = if v { VARIANT_TRUE } else { VARIANT_FALSE };
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_BOOL,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { boolVal: bool_val },
            }),
        },
    }
}

fn variant_ui1(v: u8) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_UI1,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { bVal: v },
            }),
        },
    }
}

fn variant_bstr(s: &str) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_BSTR,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 {
                    bstrVal: ManuallyDrop::new(BSTR::from(s)),
                },
            }),
        },
    }
}

fn variant_bstr_array(items: &[String]) -> Result<VARIANT, Box<dyn std::error::Error>> {
    let psa = unsafe { SafeArrayCreateVector(VT_BSTR, 0, items.len() as u32) };
    if psa.is_null() {
        return Err("SafeArrayCreateVector failed".into());
    }
    for (i, s) in items.iter().enumerate() {
        let bstr = BSTR::from(s.as_str());
        let idx = i as i32;
        // VT_BSTR elements: pass the BSTR handle (data pointer). Oleaut copies.
        let handle = if bstr.is_empty() {
            std::ptr::null::<u16>()
        } else {
            bstr.as_ptr()
        };
        unsafe {
            SafeArrayPutElement(psa, &idx, handle as *const _)?;
        }
    }
    Ok(VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VARENUM(VT_ARRAY.0 | VT_BSTR.0),
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { parray: psa },
            }),
        },
    })
}

fn object_to_json(obj: &IWbemClassObject) -> Result<Value, Box<dyn std::error::Error>> {
    unsafe { obj.BeginEnumeration(0) }?;
    let mut map = Map::new();
    loop {
        let mut name = BSTR::new();
        let mut val: VARIANT = unsafe { std::mem::zeroed() };
        let mut vtype = 0i32;
        let mut flavor = 0i32;
        let step = unsafe { obj.Next(0, &mut name, &mut val, &mut vtype, &mut flavor) };
        // At end of enumeration `Next` yields WBEM_S_NO_MORE_DATA — a *success* HRESULT
        // in windows-rs (`Ok`) — with an empty name. Guard on both to avoid an infinite loop.
        if step.is_err() || name.is_empty() {
            unsafe {
                let _ = VariantClear(&mut val);
            }
            break;
        }
        let key = name.to_string();
        if !key.starts_with("__") {
            map.insert(key, variant_to_json(&val));
        }
        unsafe {
            let _ = VariantClear(&mut val);
        }
    }
    let _ = unsafe { obj.EndEnumeration() };
    Ok(Value::Object(map))
}

fn variant_to_json(v: &VARIANT) -> Value {
    unsafe {
        let inner = &v.Anonymous.Anonymous;
        let vt = inner.vt;
        let anon = &inner.Anonymous;
        let base = VARENUM(vt.0 & 0x0FFF);
        if vt.0 & VT_ARRAY.0 != 0 {
            return safearray_to_json(anon.parray, base);
        }
        match base {
            VT_EMPTY | VT_NULL => Value::Null,
            VT_BOOL => json!(anon.boolVal.0 != 0),
            VT_UI1 => json!(anon.bVal),
            VT_I2 => json!(anon.iVal),
            VT_UI2 => json!(anon.uiVal),
            VT_I4 => json!(anon.lVal),
            VT_UI4 => json!(anon.ulVal),
            VT_I8 => json!(anon.llVal),
            VT_UI8 => json!(anon.ullVal),
            VT_R8 | VT_DATE => json!(anon.dblVal),
            VT_BSTR => {
                let s = (*anon.bstrVal).to_string();
                if s.is_empty() {
                    Value::Null
                } else {
                    Value::String(s)
                }
            },
            _ => Value::String(format!("<vt:{}>", vt.0)),
        }
    }
}

fn safearray_to_json(
    psa: *mut windows::Win32::System::Com::SAFEARRAY,
    base: VARENUM,
) -> Value {
    if psa.is_null() {
        return Value::Array(vec![]);
    }
    unsafe {
        let Ok(lbound) = SafeArrayGetLBound(psa, 1) else {
            return Value::Array(vec![]);
        };
        let Ok(ubound) = SafeArrayGetUBound(psa, 1) else {
            return Value::Array(vec![]);
        };
        let mut out = Vec::new();
        for i in lbound..=ubound {
            match base {
                VT_BSTR => {
                    let mut bstr = BSTR::new();
                    if SafeArrayGetElement(psa, &i, &mut bstr as *mut _ as *mut _).is_ok() {
                        out.push(Value::String(bstr.to_string()));
                    }
                },
                VT_BOOL => {
                    let mut b = VARIANT_FALSE;
                    if SafeArrayGetElement(psa, &i, &mut b as *mut _ as *mut _).is_ok() {
                        out.push(json!(b.0 != 0));
                    }
                },
                VT_I4 | VT_UI4 => {
                    let mut n = 0i32;
                    if SafeArrayGetElement(psa, &i, &mut n as *mut _ as *mut _).is_ok() {
                        out.push(json!(n));
                    }
                },
                _ => out.push(Value::String(format!("<elem vt:{}>", base.0))),
            }
        }
        Value::Array(out)
    }
}

// --- public high-level ops ---

pub fn get_status() -> Result<Value, Box<dyn std::error::Error>> {
    DefenderWmi::connect()?.query_class("MSFT_MpComputerStatus")
}

pub fn get_preference() -> Result<Value, Box<dyn std::error::Error>> {
    DefenderWmi::connect()?.query_class("MSFT_MpPreference")
}

pub fn get_threat_detections() -> Result<Value, Box<dyn std::error::Error>> {
    DefenderWmi::connect()?.query_class("MSFT_MpThreatDetection")
}

pub fn get_threat_catalog(
    limit: usize,
    filter: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let v = DefenderWmi::connect()?.query_class("MSFT_MpThreatCatalog")?;
    let mut rows = match v {
        Value::Array(a) => a,
        Value::Null => vec![],
        other => vec![other],
    };
    if let Some(f) = filter {
        let f = f.to_ascii_lowercase();
        rows.retain(|r| {
            r.get("ThreatName")
                .and_then(|x| x.as_str())
                .map(|n| n.to_ascii_lowercase().contains(&f))
                .unwrap_or(false)
        });
    }
    rows.truncate(limit.max(1));
    Ok(Value::Array(rows))
}

/// ScanType: 1=Quick, 2=Full, 3=Custom
pub fn start_scan(scan_type: u8, path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let wmi = DefenderWmi::connect()?;
    let mut args = vec![("ScanType", WmiArg::U8(scan_type))];
    if let Some(p) = path {
        args.push(("ScanPath", WmiArg::Str(p.to_string())));
    }
    let _ = wmi.exec_method("MSFT_MpScan", "Start", &args)?;
    Ok(())
}

pub fn update_signature() -> Result<(), Box<dyn std::error::Error>> {
    let _ = DefenderWmi::connect()?.exec_method("MSFT_MpSignature", "Update", &[])?;
    Ok(())
}

pub fn remove_threats() -> Result<(), Box<dyn std::error::Error>> {
    let _ = DefenderWmi::connect()?.exec_method("MSFT_MpThreat", "Remove", &[])?;
    Ok(())
}

pub fn preference_set(args: &[(&str, WmiArg)]) -> Result<(), Box<dyn std::error::Error>> {
    let _ = DefenderWmi::connect()?.exec_method("MSFT_MpPreference", "Set", args)?;
    Ok(())
}

pub fn preference_add(args: &[(&str, WmiArg)]) -> Result<(), Box<dyn std::error::Error>> {
    let _ = DefenderWmi::connect()?.exec_method("MSFT_MpPreference", "Add", args)?;
    Ok(())
}

pub fn preference_remove(args: &[(&str, WmiArg)]) -> Result<(), Box<dyn std::error::Error>> {
    let _ = DefenderWmi::connect()?.exec_method("MSFT_MpPreference", "Remove", args)?;
    Ok(())
}

// keep `w!` available for future static method names
#[allow(dead_code)]
fn _w_start() -> PCWSTR {
    w!("Start")
}
