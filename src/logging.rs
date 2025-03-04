use env_logger::{Builder, Env};
use log::{LevelFilter, info};
use std::fs;
use std::io::Write;
use chrono::Local;

pub fn init_logging() {
    // Create logs directory if it doesn't exist
    fs::create_dir_all("logs").expect("Failed to create logs directory");

    // Generate timestamp for log file
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_file = format!("logs/app_{}.log", timestamp);

    // Get the log level from environment variable or default to "info"
    let env = Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");

    // Create the log file
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .expect("Failed to open log file");

    // Initialize the logger with custom format
    Builder::from_env(env)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        // Write only to file
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();

    info!("Log file created at: {}", log_file);
} 