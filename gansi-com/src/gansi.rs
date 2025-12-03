#![allow(non_camel_case_types)]

mod antimalware;
mod attribute;
mod keywords;
mod report;
mod scan;

use core::result::Result;
use std::{
    cell::RefCell,
    path::Path,
    sync::{Arc, atomic::AtomicU32},
};

use antimalware::{PsVersion, ScriptType};
use fern::Dispatch;
use log::{LevelFilter, debug, error};
use ps_parser::{PowerShellSession, Variables};
use report::PipeClient;
use shared::{PipeName, constants::GANSI_PIPE_SUFFIX, win_log};
use tokio::sync::RwLock;
use windows::Win32::System::{
    Antimalware::*,
    Com::{IClassFactory, IClassFactory_Impl},
};
use windows_core::*;
use winreg::{RegKey, enums::*};

use crate::utils::ProcessInfo;
pub(super) static mut CLASS_FACTORY: Option<StaticComObject<Gansi>> = None;

#[interface("b8614e83-84ac-45fb-82a8-21711aaf07f2")]
unsafe trait IGansi: IAntimalwareProvider2 {}

#[implement(IGansi, IClassFactory)]
pub struct Gansi {
    ps_session: RefCell<PowerShellSession>,
    process_info: ProcessInfo,
    request_number: AtomicU32,
    pipe_client: Arc<RwLock<PipeClient>>,
}

impl Gansi {
    fn get_pipe_name() -> Result<String, Box<dyn std::error::Error>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let uuid_path_string = format!("Software\\Classes\\CLSID\\{}", Gansi::IID());
        let uuid_path = Path::new(uuid_path_string.as_str());
        let key = hklm.open_subkey(uuid_path)?;
        let pipe_suffix: String = key.get_value("pipe")?;
        let pipe_name = PipeName::from_suffix(&pipe_suffix);

        pipe_name.verify()?;
        Ok(pipe_name.to_string())
    }

    pub fn new() -> Self {
        let process_info = ProcessInfo::current();

        if let Err(err) = Self::init_logging(LevelFilter::Info, &process_info) {
            error!("Failed to initialize logging: {err}");
        }

        let pipe_name = match Self::get_pipe_name() {
            Ok(name) => name,
            Err(err) => {
                error!("Failed to get pipe name: {err}");
                format!(r"\\.\pipe\{}", GANSI_PIPE_SUFFIX)
            },
        };

        Self {
            ps_session: RefCell::new(PowerShellSession::new().with_variables(Variables::env())),
            process_info,
            request_number: AtomicU32::new(0),
            pipe_client: Arc::new(RwLock::new(PipeClient::new(&pipe_name))),
        }
    }

    fn init_logging(
        log_level: LevelFilter,
        process_info: &ProcessInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base = format!("amsi-{}-{}", process_info.pid(), process_info.tid());
        let log_dir = "C:\\gansi";

        let mut logger = Dispatch::new().format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}::{}] {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S %Z"),
                record.level().short(),
                record.target(),
                record.line().unwrap_or(0),
                message,
            ))
        });

        logger = logger.chain(
            Dispatch::new()
                .level(LevelFilter::Off)
                .level_for("gansi_com", log_level)
                .chain(fern::DateBased::new(
                    log_dir,
                    format!("/{base}-%Y-%m-%d.log"),
                )),
        );

        logger.apply()?;

        Ok(())
    }
}

pub trait ShortName {
    fn short(&self) -> String;
}

impl ShortName for log::Level {
    fn short(&self) -> String {
        match self {
            Self::Info => "INF",
            Self::Warn => "WRN",
            Self::Error => "ERR",
            Self::Debug => "DBG",
            Self::Trace => "VER",
        }
        .to_owned()
    }
}

impl IGansi_Impl for Gansi_Impl {}

impl IClassFactory_Impl for Gansi_Impl {
    fn CreateInstance(
        &self,
        _: windows_core::Ref<'_, IUnknown>,
        iid: *const windows_core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> windows_core::Result<()> {
        win_log!("Gansi::CreateInstance");
        Self::query_interface(iid, interface)
    }

    fn LockServer(&self, _: BOOL) -> windows_core::Result<()> {
        win_log!("Gansi::LockServer");
        Ok(())
    }
}

impl Gansi {
    pub const NAME: &str = "Gansi";
    // UTF-16 "Gansi\0"
    pub const DISPLAY_NAME: &[u16] = &[0x47u16, 0x61, 0x6E, 0x73, 0x69, 0x0];
}

impl Gansi {
    pub fn IID() -> String {
        format!("{{{:?}}}", IGansi::IID)
    }
}

impl Gansi_Impl {
    pub fn get_class_object(
        rclsid: *const ::windows_core::GUID,
        iid: *const ::windows_core::GUID,
        interface: *mut *mut ::core::ffi::c_void,
    ) -> windows_core::HRESULT {
        if rclsid.is_null() || IGansi::IID != unsafe { *rclsid } {
            debug!(
                "Gansi_Impl::get_class_object: Unsupported IID: {:?}",
                unsafe { *iid }
            );
            return windows_core::HRESULT(-2147221231); // E_NOINTERFACE
        }

        if let Err(r) = Self::query_interface(iid, interface) {
            debug!("Gansi_Impl::get_class_object: {:?}", r);
            return r.into();
        }
        windows_core::HRESULT(0)
    }

    fn query_interface(
        iid: *const windows_core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> windows_core::Result<()> {
        let class_factory = unsafe { CLASS_FACTORY.as_ref() };
        let Some(class_factory) = class_factory else {
            debug!("Gansi_Impl::get_class_object: CLASS_FACTORY is None");
            return Err(windows_core::HRESULT(-1).into());
        };
        let hr = unsafe { class_factory.QueryInterface(iid, interface) };
        if hr.is_err() {
            debug!("Gansi_Impl::query_interface: {:?}", hr);
            return Err(hr.into());
        }

        Ok(())
    }

    pub fn create() {
        debug!("Gansi_Impl::create");
        unsafe { CLASS_FACTORY = Some(Gansi::new().into_static()) };
    }

    pub fn terminate() -> bool {
        let class_factory = unsafe { CLASS_FACTORY.take() };
        let Some(class_factory) = class_factory else {
            debug!("Gansi_Impl::terminate: CLASS_FACTORY is None");
            return false;
        };
        let released = class_factory.count.release();
        debug!("Remaining: {released}");
        released == 0
    }
}
