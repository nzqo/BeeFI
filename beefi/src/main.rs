use clap::Parser;
use simplelog::SimpleLogger;

mod capture;
mod cli;
mod monitor_mode;

use cli::{Cli, Commands, MonitorArgs};

fn main() {
    let cli = Cli::parse();

    SimpleLogger::init(
        cli.loglevel,
        simplelog::ConfigBuilder::new()
            .add_filter_allow("beefi".into())
            .build(),
    )
    .expect("Failed to initialize logger");

    match cli.command {
        Commands::Capture(args) => capture::run_online_capture(args),
        Commands::FromPcap(args) => capture::run_offline_capture(args),
        Commands::MonitorMode(MonitorArgs {
            interface,
            channel,
            bandwidth,
        }) => monitor_mode::monitor_mode(&interface, channel, bandwidth).unwrap(),
    }
}
