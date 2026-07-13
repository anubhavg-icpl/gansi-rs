mod com_wrapper;
mod defender;
mod pipe_server;
mod ui;

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use clap::{Parser, Subcommand};
use com_wrapper::{ComWrapper, GansiComWrapper};
use defender::DefenderCmd;
use shared::{FfiString, GansiMessage, PipeName, constants::GANSI_PIPE_SUFFIX};
use tokio::{runtime::Runtime, time::timeout};

use crate::pipe_server::PipeError;

const GANSI_COM_DLL: &str = "gansi_com.dll";

static CONTROL_C: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));
static EVENT_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

#[derive(Parser, Debug)]
#[command(
    name = "gansi",
    bin_name = "gansi",
    author,
    version,
    about = "Gansi — Windows AMSI provider + Defender control plane",
    long_about = "Register, unregister, and live-trace the Gansi AMSI COM provider.\n\
                  Manage Microsoft Defender Antivirus via native WMI \
                  (ROOT\\Microsoft\\Windows\\Defender — no PowerShell).\n\
                  Requires Windows; elevation for registration and most Defender preference changes.",
    propagate_version = true,
    styles = clap_styles(),
    disable_help_subcommand = true,
    after_help = "Examples:\n  \
        gansi register\n  \
        gansi watch\n  \
        gansi defender health\n  \
        gansi defender status\n  \
        gansi defender scan --kind quick\n  \
        gansi defender exclude add --path C:\\lab\\gansi\n  \
        gansi defender lab-prep --dir .\\dist\n  \
        gansi defender realtime status\n"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, global = true, default_value = "warn", env = "GANSI_LOG")]
    log: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Register the COM + AMSI provider
    #[command(visible_alias = "r", short_flag = 'r')]
    Register {
        /// Path to gansi_com.dll
        #[arg(long, short = 'd', default_value = GANSI_COM_DLL, value_name = "PATH")]
        dll: String,

        /// Named-pipe suffix (\\.\pipe\<suffix>)
        #[arg(long, short = 'p', default_value = GANSI_PIPE_SUFFIX, value_name = "SUFFIX")]
        pipe: String,
    },

    /// Unregister the COM + AMSI provider
    #[command(visible_alias = "u", short_flag = 'u')]
    Unregister {
        /// Path to gansi_com.dll
        #[arg(long, short = 'd', default_value = GANSI_COM_DLL, value_name = "PATH")]
        dll: String,
    },

    /// Trace AMSI events from the named pipe
    #[command(visible_alias = "t", short_flag = 't')]
    Trace {
        /// Named-pipe suffix (\\.\pipe\<suffix>)
        #[arg(long, short = 'p', default_value = GANSI_PIPE_SUFFIX, value_name = "SUFFIX")]
        pipe: String,
    },

    /// Register the provider and trace events
    #[command(visible_alias = "a", short_flag = 'a', alias = "all")]
    Watch {
        /// Path to gansi_com.dll
        #[arg(long, short = 'd', default_value = GANSI_COM_DLL, value_name = "PATH")]
        dll: String,

        /// Named-pipe suffix (\\.\pipe\<suffix>)
        #[arg(long, short = 'p', default_value = GANSI_PIPE_SUFFIX, value_name = "SUFFIX")]
        pipe: String,
    },

    /// Microsoft Defender Antivirus management (status, scans, exclusions, prefs)
    #[command(visible_alias = "def", subcommand)]
    Defender(DefenderCmd),
}

fn clap_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects, Styles};
    Styles::styled()
        .header(AnsiColor::Magenta.on_default() | Effects::BOLD)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::Green.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Yellow.on_default())
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
}

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(cli.log.as_str()))
        .format_timestamp_secs()
        .init();

    if let Err(err) = run(cli) {
        ui::banner();
        ui::err(format!("{err:#}"));
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    ui::banner();

    match cli.command {
        Commands::Register { dll, pipe } => {
            let pipe_name = make_pipe(&pipe)?;
            ui::section("register");
            ui::kv("dll", &dll);
            ui::kv("pipe", pipe_name.as_str());
            ui::info("loading COM library…");

            let com = ComWrapper::new(&dll)?;
            com.register(FfiString::new(&pipe))?;
            ui::done_register(&dll, pipe_name.as_str());
        },
        Commands::Unregister { dll } => {
            ui::section("unregister");
            ui::kv("dll", &dll);
            ui::info("loading COM library…");

            let com = ComWrapper::new(&dll)?;
            com.unregister()?;
            ui::done_unregister(&dll);
        },
        Commands::Trace { pipe } => {
            let pipe_name = make_pipe(&pipe)?;
            ui::section("trace");
            ui::kv("mode", "listen only");
            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events(pipe_name.as_str()))?;
        },
        Commands::Watch { dll, pipe } => {
            let pipe_name = make_pipe(&pipe)?;
            ui::section("watch");
            ui::kv("dll", &dll);
            ui::kv("pipe", pipe_name.as_str());
            ui::info("registering provider…");

            let _guard = GansiComWrapper::new(&dll, FfiString::new(&pipe))?;
            ui::ok("provider registered · auto-unregister on exit");

            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events(pipe_name.as_str()))?;
        },
        Commands::Defender(cmd) => {
            defender::run(cmd)?;
        },
    }

    Ok(())
}

fn make_pipe(suffix: &str) -> Result<PipeName, Box<dyn std::error::Error>> {
    let pipe_name = PipeName::from_suffix(suffix);
    pipe_name.verify()?;
    Ok(pipe_name)
}

async fn trace_amsi_events(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    ctrlc::set_handler(move || {
        CONTROL_C.store(true, Ordering::Release);
    })
    .expect("Error setting Ctrl-C handler");

    ui::listening(pipe_name);

    let mut server = pipe_server::create_first_server(pipe_name)?;

    loop {
        if CONTROL_C.load(Ordering::Acquire) {
            break;
        }

        if timeout(Duration::from_millis(250), server.connect())
            .await
            .is_err()
        {
            continue;
        }

        let mut connected_client = server;
        server = pipe_server::create_server(pipe_name)?;

        ui::info("client connected");

        let _client = tokio::spawn(async move {
            loop {
                if CONTROL_C.load(Ordering::Acquire) {
                    break;
                }

                match pipe_server::message::<GansiMessage>(&mut connected_client, 250).await {
                    Ok(input_message) => {
                        let n = EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        ui::event_line(n, &input_message.to_string());
                    },
                    Err(err) => match err {
                        PipeError::Timeout => {},
                        PipeError::UnexpectedEof => {
                            ui::warn("client disconnected");
                            break;
                        },
                        PipeError::IoError(err) => {
                            log::debug!("pipe io: {err}");
                            break;
                        },
                    },
                }
            }
        });
    }

    ui::goodbye(EVENT_COUNT.load(Ordering::Relaxed));
    Ok(())
}
