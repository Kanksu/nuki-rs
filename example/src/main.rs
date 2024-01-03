
use home::home_dir;
use std::path::PathBuf;
use whoami;

use nuki_rs::{NukiSmartLock, nuki_command::LockAction};
use tokio;
use clap::{Parser, Subcommand, Args};
use env_logger::Env;

use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct App {
    /// Log level (error, warn, info, debug, trace)
    #[arg(short, long, default_value_t = log::Level::Warn)]
    log_level: log::Level,

    /// Key file, Default ~/.nuki-key
    #[arg(short, long)]
    key_file: Option<PathBuf>,

    /// Action to take, Default = status
    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Query current status (Default command)
    Status,

    /// Perform unlock action
    Lock,

    /// Perfrom lock action
    Unlock,

    /// Perfom unlatch action
    Unlatch,

    /// Query battery report
    Battery,

    /// Pair a Nuki Smart Lock
    Pair(PairArgs),
}

#[derive(Args, Debug)]
struct PairArgs {
    /// A name which will be stored in Nuki Device (Default: system user name)
    #[arg(short, long)]
    name: Option<String>
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let app = App::parse();

    let key_file = match app.key_file {
        Some(p) => p,
        None => {
            match home_dir() {
                Some(h_dir) => h_dir.join(".nuki-key"),
                None => PathBuf::from(".nuki-key"),
            }
        }
    };

    println!("Using key file: {}", &key_file.as_os_str().to_string_lossy());

    match app.command {
        Some(Command::Lock) => {
            lock_action(&key_file, LockAction::Lock).await?;
        },
        Some(Command::Unlock) => {
            lock_action(&key_file, LockAction::Unlock).await?;
        },
        Some(Command::Unlatch) => {
            lock_action(&key_file, LockAction::Unlatch).await?;
        },
        Some(Command::Pair(args)) => {
            let name = match args.name {
                Some(n) => n,
                None => {
                    println!("For registgration, the system user name <{}> is used.", whoami::username());
                    whoami::username()
                }
            };
            let registration = format!("{}@{}", name, whoami::devicename());
            pair(&key_file, &registration).await?;
        },
        Some(Command::Battery) => {
            battery_report(&key_file).await?
        }
        _ => {
            status(&key_file).await?;
        },
    }
    Ok(())
 }

 async fn pair(key_file: &PathBuf, name: &str) -> Result<()> {
    println!("Push the Button on Nuki for 5 seconds to pair.");
    println!("Discovering pairable Nuki Smart lock...");
    let mut nuki = NukiSmartLock::discover_pairable().await?;
    println!("Pairing to Nuki: {}", nuki);
    nuki.pair(name).await?;
    println!("Pairing successful. User has been authorized.");
    nuki.save(key_file)?;
    println!("Credential key has been stored to key file: {}.", key_file.as_os_str().to_string_lossy());
    Ok(())
 }

 async fn lock_action(key_file: &PathBuf, action: LockAction) -> Result<()>{
    let nuki = NukiSmartLock::load(key_file)?;
    nuki.perform_lock_action(action, &whoami::username()).await?;
    println!("Done.");
    Ok(())
 }

 async fn status(key_file: &PathBuf) -> Result<()> {
    let nuki = NukiSmartLock::load(key_file)?;
    let status = nuki.get_status().await?;
    println!("{}", status);
    Ok(())
 }

 async fn battery_report(key_file: &PathBuf) -> Result<()> {

    let nuki = NukiSmartLock::load(key_file)?;
    let report = nuki.get_battery_report().await?;
    println!("{}", report);
    Ok(())
 }
