use std::error::Error;

use clap::Parser;
use env_logger::Env;
use maybe_async::*;
use smb_cli::*;

#[cfg(not(feature = "async"))]
fn main() -> Result<(), Box<dyn Error>> {
    _main().or_else(|e| {
        log::error!("Error: {}", e);
        Err(e)
    })
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    _main().await.or_else(|e| {
        log::error!("Error: {}", e);
        Err(e)
    })
}

#[maybe_async]
async fn _main() -> Result<(), Box<dyn Error>> {
    // Use env_logger, and set default log level to info.
    // This can be overridden by setting the RUST_LOG environment variable.
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    log::info!("Starting smb-cli");
    log::info!("Version: {}", env!("CARGO_PKG_VERSION"));

    log::info!{"Profiling enabled. Attach the profiler, and press any key to continue."};
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    log::info!{"Profiler attached. Starting."};

    let cli = Cli::parse();

    // In macOS, we need to attach, since local network connections are problematic when
    // the debugger starts the process.
    #[cfg(all(feature = "profiling", target_os = "macos"))]
    {
        println!("Profiling enabled on macOS. Attach profiler, and Enter to begin running.");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }

    match &cli.command {
        Commands::Copy(cmd) => {
            log::info!("Copying {:?} to {:?}", cmd.from, cmd.to);
            copy::copy(&cmd, &cli).await?;
        }
        Commands::Info(cmd) => {
            log::info!("Getting info for {:?}", cmd.path);
            info::info(&cmd, &cli).await?;
        }
    }

    Ok(())
}
