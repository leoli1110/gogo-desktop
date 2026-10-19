//! Windows service: `gogo service install | uninstall`.

use crate::config::Config;
use anyhow::Result;
use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "GogoDesktop";
const DISPLAY: &str = "Gogo Desktop";

pub fn install() -> Result<()> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe = std::env::current_exe()?;
    let info = ServiceInfo {
        name: OsString::from(NAME),
        display_name: OsString::from(DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem: needed to read the NTFS change journal
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    svc.set_description("Fast local file search in your browser (http://127.0.0.1:4680)")?;
    svc.start::<&str>(&[])?;
    println!("Installed and started the {DISPLAY} service. Open http://127.0.0.1:4680, or run 'gogo signin'.");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(500));
            if svc.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
        }
    }
    svc.delete()?;
    println!("Removed the {DISPLAY} service. Your data folder (%ProgramData%\\GogoDesktop) was kept.");
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> Result<()> {
    service_dispatcher::start(NAME, ffi_service_main)?;
    Ok(())
}

fn init_file_logging() {
    let dir = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"))
        .join("GogoDesktop")
        .join("logs");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("gogo.log")) {
        let filter = tracing_subscriber::EnvFilter::try_from_env("GOGO_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_target(false)
            .with_writer(std::sync::Mutex::new(file))
            .try_init();
    }
}

fn service_main(_args: Vec<OsString>) {
    init_file_logging();
    if let Err(e) = run_service() {
        tracing::error!("service stopped with an error: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let tx = std::sync::Mutex::new(Some(tx));
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(t) = tx.lock().ok().and_then(|mut g| g.take()) {
                let _ = t.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let set = |state: ServiceState, code: u32| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    set(ServiceState::Running, 0);
    let result = (|| -> Result<()> {
        let cfg = Config::from_env()?;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(crate::server::run(cfg, async move {
            let _ = rx.await;
        }))
    })();
    set(ServiceState::Stopped, if result.is_ok() { 0 } else { 1 });
    result
}
