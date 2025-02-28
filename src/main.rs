// main.rs
extern crate clap;
extern crate env_logger;
extern crate imap;
extern crate log;
extern crate native_tls;
extern crate regex;
extern crate serde;
extern crate toml;

mod config;
mod email;
mod filter;
mod imap_client;

use clap::{App, Arg};
use log::{debug, error, info};
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::process;

use config::Config;
use email::EmailProcessor;
use filter::{AiFilter, FilterEngine, RuleBasedFilter};
use imap_client::ImapClient;

fn main() {
    // Initialize the logger
    env_logger::init();

    info!("Starting Email Organizer");
    debug!("Initializing command line argument parser");

    // Parse command-line arguments
    let matches = App::new("Email Organizer")
        .version("1.0")
        .author("Your Name")
        .about("Automatically moves newsletter emails to a different folder")
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("SERVER")
                .help("IMAP server hostname")
                .required(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("IMAP server port (default: 993)")
                .default_value("993"),
        )
        .arg(
            Arg::with_name("username")
                .short("u")
                .long("username")
                .value_name("USERNAME")
                .help("Email username")
                .required(true),
        )
        .arg(
            Arg::with_name("source_folder")
                .long("source")
                .value_name("SOURCE_FOLDER")
                .help("Source folder to scan (default: INBOX)")
                .default_value("INBOX"),
        )
        .arg(
            Arg::with_name("limit")
                .long("limit")
                .value_name("LIMIT")
                .help("Maximum number of messages to process (default: process all messages)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("target_folder")
                .long("target")
                .value_name("TARGET_FOLDER")
                .help("Default target folder for newsletters")
                .required(true),
        )
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("CONFIG_FILE")
                .help("Path to TOML config file with subject regex patterns")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ai")
                .long("ai")
                .help("Use AI to classify emails instead of rule-based filtering")
                .takes_value(false),
        )
        .get_matches();

    debug!("Command line arguments parsed successfully");

    // Get environment variables
    debug!("Reading EMAIL_PASSWORD environment variable");
    let password = match env::var("EMAIL_PASSWORD") {
        Ok(val) => {
            debug!("EMAIL_PASSWORD environment variable found");
            val
        }
        Err(_) => {
            error!("EMAIL_PASSWORD environment variable not set");
            eprintln!("ERROR: EMAIL_PASSWORD environment variable not set");
            process::exit(1);
        }
    };

    // Get command line parameters
    let server = matches.value_of("server").unwrap();
    let port: u16 = matches.value_of("port").unwrap().parse().unwrap_or(993);
    let username = matches.value_of("username").unwrap();
    let source_folder = matches.value_of("source_folder").unwrap();
    let target_folder = matches.value_of("target_folder").unwrap();
    let message_limit = matches.value_of("limit").map(|l| l.parse::<usize>().unwrap_or(0));
    let use_ai = matches.is_present("ai");

    debug!("Server: {}:{}", server, port);
    debug!("Username: {}", username);
    debug!("Source folder: {}", source_folder);
    debug!("Target folder: {}", target_folder);
    if let Some(limit) = message_limit {
        debug!("Message limit: {}", limit);
    }
    debug!("Using AI: {}", use_ai);

    // Read config file if provided
    let config = if let Some(config_path) = matches.value_of("config") {
        debug!("Reading config file: {}", config_path);
        match Config::from_file(config_path) {
            Ok(cfg) => {
                debug!(
                    "Config loaded successfully with {} subject rules",
                    cfg.subject_rules.len()
                );
                Some(cfg)
            }
            Err(e) => {
                error!("Failed to read config file: {}", e);
                eprintln!("Error reading config file: {}", e);
                process::exit(1);
            }
        }
    } else if !use_ai {
        debug!("No config file provided, using only built-in newsletter detection");
        Some(Config::default())
    } else {
        None
    };

    // Create IMAP client
    let mut imap_client = ImapClient::new(server, port, username, &password);

    // Connect and get folder information
    info!("Connecting to server to retrieve folder list");
    let folders = match imap_client.get_folders() {
        Ok(folders) => {
            info!("Successfully retrieved {} folders", folders.len());
            folders
        }
        Err(e) => {
            error!("Error connecting to server: {}", e);
            eprintln!("Error connecting to server: {}", e);
            process::exit(1);
        }
    };

    // Create appropriate filter engine based on command line options
    let filter_engine: Box<dyn FilterEngine> = if use_ai {
        info!("Using AI-based email filtering");
        Box::new(AiFilter::new(folders.clone(), target_folder.to_string(), "http://localhost:1234".to_string()))
    } else {
        info!("Using rule-based email filtering");
        Box::new(RuleBasedFilter::new(
            config.unwrap(),
            target_folder.to_string(),
        ))
    };

    // Print information about what the program will do
    print_program_info(
        server,
        port,
        username,
        source_folder,
        target_folder,
        &filter_engine,
        &folders,
    );

    // Collect all unique target folders
    let unique_folders = filter_engine.get_target_folders();

    // Ask for confirmation
    info!("Asking for user confirmation");
    println!("\nTarget folders that will be used:");
    for folder in &unique_folders {
        println!("  - {}", folder);
    }

    print!(
        "\nDo you want to proceed with organizing emails from '{}'? (y/n): ",
        source_folder
    );
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    if input.trim().to_lowercase() != "y" {
        info!("User cancelled the operation");
        println!("Operation cancelled by user.");
        process::exit(0);
    }

    // Process emails
    info!("User confirmed. Proceeding with email processing");
    let email_processor = EmailProcessor::new(filter_engine);
    match email_processor.process_emails(&mut imap_client, source_folder, message_limit) {
        Ok(moved_counts) => {
            print_results(&moved_counts);
        }
        Err(e) => {
            error!("Error processing emails: {}", e);
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn print_program_info(
    server: &str,
    port: u16,
    username: &str,
    source_folder: &str,
    target_folder: &str,
    filter: &Box<dyn FilterEngine>,
    folders: &[String],
) {
    // Print information to logs
    info!("=== Email Newsletter Organizer ===");
    info!("IMAP Server: {}:{}", server, port);
    info!("Username: {}", username);
    info!("Source folder: {}", source_folder);
    info!("Default target folder: {}", target_folder);

    // Print information to console
    println!("=== Email Newsletter Organizer ===");
    println!("IMAP Server: {}:{}", server, port);
    println!("Username: {}", username);
    println!("Source folder: {}", source_folder);
    println!("Default target folder: {}", target_folder);

    // Print filter info
    filter.print_info();

    // Display available folders
    info!("Displaying available folders");
    println!("\nAvailable folders on the server:");
    for (i, folder) in folders.iter().enumerate() {
        println!("  {}. {}", i + 1, folder);
    }
}

fn print_results(moved_counts: &HashMap<String, usize>) {
    let total_moved: usize = moved_counts.values().sum();

    if total_moved > 0 {
        info!("Successfully moved {} messages", total_moved);
        println!("\nSuccessfully moved {} messages:", total_moved);

        for (folder, count) in moved_counts {
            if *count > 0 {
                println!("  - {} to '{}'", count, folder);
            }
        }
    } else {
        info!("No messages found to move");
        println!("No messages found to move");
    }
}