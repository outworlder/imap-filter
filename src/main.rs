extern crate clap;
extern crate env_logger;
extern crate imap;
extern crate log;
extern crate native_tls;
extern crate regex;
extern crate serde;
extern crate toml;

use log::{debug, error, info, trace, warn};
use serde::Deserialize;
use std::fs::File;
use std::io::{self, Read, Write};

use clap::{App, Arg};
use imap::Session;
use native_tls::TlsStream;
use regex::Regex;
use std::env;
use std::net::TcpStream;
use std::process;

#[derive(Debug, Deserialize)]
struct Config {
    subject_rules: Vec<SubjectRule>,
    #[serde(default)]
    sender_rules: Vec<SenderRule>,
}

#[derive(Debug, Deserialize)]
struct SubjectRule {
    pattern: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SenderRule {
    pattern: String,
    description: Option<String>,
}

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
            Arg::with_name("target_folder")
                .long("target")
                .value_name("TARGET_FOLDER")
                .help("Target folder for newsletters")
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

    debug!("Server: {}:{}", server, port);
    debug!("Username: {}", username);
    debug!("Source folder: {}", source_folder);
    debug!("Target folder: {}", target_folder);

    // Read config file if provided
    let config = if let Some(config_path) = matches.value_of("config") {
        debug!("Reading config file: {}", config_path);
        match read_config(config_path) {
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
    } else {
        debug!("No config file provided, using only built-in newsletter detection");
        None
    };

    // Print information about what the program will do
    info!("=== Email Newsletter Organizer ===");
    info!("IMAP Server: {}:{}", server, port);
    info!("Username: {}", username);
    info!("Source folder: {}", source_folder);
    info!("Target folder: {}", target_folder);
    if let Some(cfg) = &config {
        info!(
            "Using {} subject regex rules from config file",
            cfg.subject_rules.len()
        );
        if !cfg.sender_rules.is_empty() {
            info!(
                "Using {} sender regex rules from config file",
                cfg.sender_rules.len()
            );
        }
    }

    println!("=== Email Newsletter Organizer ===");
    println!("IMAP Server: {}:{}", server, port);
    println!("Username: {}", username);
    println!("Source folder: {}", source_folder);
    println!("Target folder: {}", target_folder);
    if let Some(cfg) = &config {
        println!(
            "Using {} subject regex rules from config file",
            cfg.subject_rules.len()
        );
        if !cfg.sender_rules.is_empty() {
            println!(
                "Using {} sender regex rules from config file",
                cfg.sender_rules.len()
            );
        }

        println!("\nConfigured subject patterns:");
        for (i, rule) in cfg.subject_rules.iter().enumerate() {
            if let Some(desc) = &rule.description {
                println!("  {}. {} - {}", i + 1, rule.pattern, desc);
            } else {
                println!("  {}. {}", i + 1, rule.pattern);
            }
        }

        if !cfg.sender_rules.is_empty() {
            println!("\nConfigured sender patterns:");
            for (i, rule) in cfg.sender_rules.iter().enumerate() {
                if let Some(desc) = &rule.description {
                    println!("  {}. {} - {}", i + 1, rule.pattern, desc);
                } else {
                    println!("  {}. {}", i + 1, rule.pattern);
                }
            }
        }
    }

    // Connect and get folder information
    info!("Connecting to server to retrieve folder list");
    let folders = match get_folders(server, port, username, &password) {
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

    // Display available folders
    info!("Displaying available folders");
    println!("\nAvailable folders on the server:");
    for (i, folder) in folders.iter().enumerate() {
        println!("  {}. {}", i + 1, folder);
    }

    // Ask for confirmation
    info!("Asking for user confirmation");
    print!(
        "\nDo you want to proceed with moving newsletters from '{}' to '{}'? (y/n): ",
        source_folder, target_folder
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

    // Connect to the server and process emails
    info!("User confirmed. Proceeding with email processing");
    match connect_and_process(
        server,
        port,
        username,
        &password,
        source_folder,
        target_folder,
        config.as_ref(),
    ) {
        Ok(moved_count) => {
            if moved_count > 0 {
                info!(
                    "Successfully moved {} newsletter messages to {}",
                    moved_count, target_folder
                );
                println!(
                    "Successfully moved {} newsletter messages to {}",
                    moved_count, target_folder
                );
            } else {
                info!("No newsletter messages found to move");
                println!("No newsletter messages found to move");
            }
        }
        Err(e) => {
            error!("Error processing emails: {}", e);
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn read_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

fn get_folders(
    server: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Setup TLS
    debug!("Setting up TLS connection");
    let tls = native_tls::TlsConnector::builder().build()?;

    // Connect to the server
    debug!("Connecting to IMAP server {}:{}", server, port);
    let client = imap::connect((server, port), server, &tls)?;

    // Login
    debug!("Logging in as user: {}", username);
    let mut session = match client.login(username, password) {
        Ok(session) => {
            debug!("Login successful");
            session
        }
        Err((err, _client)) => {
            error!("Login failed: {}", err);
            return Err(Box::new(err));
        }
    };

    // Skip retrieving capabilities to avoid recursion limit issues
    debug!("Skipping server capabilities retrieval");

    // Get all folders
    debug!("Requesting folder list");
    let folders = session.list(None, Some("*"))?;

    // Convert folder names to strings
    let mut folder_names = Vec::new();
    for folder in &folders {
        trace!("Found folder: {}", folder.name());
        folder_names.push(folder.name().to_string());
    }

    // Log out
    debug!("Logging out");
    session.logout()?;

    debug!("Retrieved {} folders", folder_names.len());
    Ok(folder_names)
}

fn connect_and_process(
    server: &str,
    port: u16,
    username: &str,
    password: &str,
    source_folder: &str,
    target_folder: &str,
    config: Option<&Config>,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Setup TLS
    let tls = native_tls::TlsConnector::builder().build()?;

    // Connect to the server
    let client = imap::connect((server, port), server, &tls)?;

    // Login - handle the error manually since it returns a tuple
    let mut session = match client.login(username, password) {
        Ok(session) => session,
        Err((err, _client)) => return Err(Box::new(err)),
    };

    // Ensure target folder exists
    let folders = session.list(None, Some("*"))?;
    let mut target_exists = false;
    for folder in &folders {
        if folder.name() == target_folder {
            target_exists = true;
            break;
        }
    }

    if !target_exists {
        session.create(target_folder)?;
        println!("Created folder: {}", target_folder);
    }

    // Select the source mailbox
    session.select(source_folder)?;

    // Search for all messages
    let messages = session.fetch("1:*", "(UID ENVELOPE BODY.PEEK[HEADER.FIELDS (LIST-ID LIST-UNSUBSCRIBE X-MAILCHIMP-ID X-CAMPAIGN X-MAILER)])")?;
    let mut newsletter_ids: Vec<String> = Vec::new();

    // First pass: identify newsletters
    println!("\nScanning messages for newsletters and pattern matches...");
    let total_messages = messages.iter().count();
    let bar_width = 50;

    let mut newsletter_ids = Vec::new();
    let mut match_reasons = Vec::new();

    for (i, message) in messages.iter().enumerate() {
        // Update progress bar
        let progress = (i as f32 / total_messages as f32 * bar_width as f32) as usize;
        print!(
            "\r[{:<50}] {}/{}",
            "#".repeat(progress),
            i + 1,
            total_messages
        );
        io::stdout().flush()?;

        let uid = message.uid.unwrap_or(0);
        if uid == 0 {
            warn!("Message has UUID 0");
            continue;
        }

        let mut matched = false;
        let mut reason = String::new();

        // Check headers for newsletter indicators
        if let Some(body) = message.body().or_else(|| message.text()) {
            let headers = std::str::from_utf8(body)?;

            if is_newsletter(headers) {
                matched = true;
                reason = "Newsletter headers".to_string();
            }
        }

        // Check subject against regex patterns if config is provided
        if !matched && config.is_some() {
            if let Some(envelope) = message.envelope() {
                if let Some(subject_bytes) = envelope.subject {
                    // Try to convert subject to string, handling encoding issues gracefully
                    let subject_str = match std::str::from_utf8(&subject_bytes) {
                        Ok(s) => s.to_string(),
                        Err(_) => String::from_utf8_lossy(&subject_bytes).to_string(),
                    };

                    // Check subject against patterns
                    debug!("Checking subject patterns");
                    if let Some(pattern_match) =
                        check_subject_patterns(&subject_str, &config.unwrap().subject_rules)
                    {
                        matched = true;
                        reason = format!("Subject pattern: {}", pattern_match);
                    }
                } else {
                    debug!("NO MESSAGE ENVELOPE")
                }
            }
        }

        // Check sender against regex patterns if config is provided and not already matched
        if !matched && config.is_some() && !config.unwrap().sender_rules.is_empty() {
            if let Some(envelope) = message.envelope() {
                if let Some(from_addresses) = &envelope.from {
                    for address in from_addresses {
                        // Build sender string from address components
                        let mut sender = String::new();

                        // Add name if available
                        if let Some(name_bytes) = &address.name {
                            match std::str::from_utf8(name_bytes) {
                                Ok(name) => {
                                    sender.push_str(name);
                                    sender.push_str(" ");
                                }
                                Err(_) => {
                                    let name = String::from_utf8_lossy(name_bytes);
                                    sender.push_str(&name);
                                    sender.push_str(" ");
                                }
                            }
                        }

                        // Add email address
                        sender.push_str("<");

                        // Add mailbox (username) part
                        if let Some(mailbox_bytes) = &address.mailbox {
                            match std::str::from_utf8(mailbox_bytes) {
                                Ok(mailbox) => {
                                    sender.push_str(mailbox);
                                }
                                Err(_) => {
                                    let mailbox = String::from_utf8_lossy(mailbox_bytes);
                                    sender.push_str(&mailbox);
                                }
                            }
                        }

                        // Add @ symbol if we have both mailbox and host
                        if address.mailbox.is_some() && address.host.is_some() {
                            sender.push_str("@");
                        }

                        // Add host (domain) part
                        if let Some(host_bytes) = &address.host {
                            match std::str::from_utf8(host_bytes) {
                                Ok(host) => {
                                    sender.push_str(host);
                                }
                                Err(_) => {
                                    let host = String::from_utf8_lossy(host_bytes);
                                    sender.push_str(&host);
                                }
                            }
                        }

                        sender.push_str(">");

                        // Check if this sender matches any patterns
                        if let Some(pattern_match) =
                            check_sender_patterns(&sender, &config.unwrap().sender_rules)
                        {
                            matched = true;
                            reason = format!("Sender pattern: {}", pattern_match);
                            break; // No need to check other addresses
                        }
                    }
                }
            }
        }

        // Add to ids list if matched
        if matched {
            newsletter_ids.push(uid.to_string());
            match_reasons.push((uid.to_string(), reason));
        }
    }

    // Clear the progress line
    println!(
        "\r[{}] {}/{}",
        "#".repeat(bar_width),
        total_messages,
        total_messages
    );

    let moved_count = newsletter_ids.len();

    // Move identified newsletters if any were found
    if !newsletter_ids.is_empty() {
        println!(
            "\nMoving {} newsletters to '{}'...",
            moved_count, target_folder
        );

        // Move messages in batches to show progress
        let batch_size = 10.max(moved_count / 20).min(moved_count); // At least 10, at most all, aim for ~20 batches
        let mut moved = 0;
        let mut failed_ids: Vec<String> = Vec::new();

        while moved < moved_count {
            let end = (moved + batch_size).min(moved_count);
            let batch = &newsletter_ids[moved..end];
            let uid_batch = batch.join(",");

            match session.uid_mv(&uid_batch, target_folder) {
                Ok(_) => {
                    moved += batch.len();
                }
                Err(e) => {
                    eprintln!("\nError moving messages {}: {}", uid_batch, e);
                    // Try moving individual messages to identify which ones are problematic
                    for uid in batch {
                        match session.mv(uid, target_folder) {
                            Ok(_) => {
                                moved += 1;
                            }
                            Err(e) => {
                                eprintln!("Failed to move message with UID {}: {}", uid, e);
                                failed_ids.push(uid.clone());
                            }
                        }
                    }
                }
            }

            // Update progress bar
            let progress = (moved as f32 / moved_count as f32 * bar_width as f32) as usize;
            print!("\r[{:<50}] {}/{}", "#".repeat(progress), moved, moved_count);
            io::stdout().flush()?;
        }

        // Report failures if any
        if !failed_ids.is_empty() {
            eprintln!(
                "\nWarning: Failed to move {} messages: {}",
                failed_ids.len(),
                failed_ids.join(", ")
            );
        }

        println!(); // Final newline after progress bar
    }

    // Logout
    session.logout()?;

    Ok(moved_count)
}

fn is_newsletter(headers: &str) -> bool {
    trace!("Checking headers for newsletter indicators");

    // Check for common newsletter headers
    if headers.contains("List-ID:") {
        trace!("Found List-ID header");
        return true;
    }
    if headers.contains("List-Unsubscribe:") {
        trace!("Found List-Unsubscribe header");
        return true;
    }
    if headers.contains("X-Mailchimp-ID:") {
        trace!("Found X-Mailchimp-ID header");
        return true;
    }
    if headers.contains("X-Campaign") {
        trace!("Found X-Campaign header");
        return true;
    }

    // Check for common newsletter senders
    let sender_regex =
        Regex::new(r"(?i)From:.*?(newsletter|digest|updates|weekly|daily|monthly|bulletin)")
            .unwrap();
    if sender_regex.is_match(headers) {
        trace!("Found newsletter keyword in From: header");
        return true;
    }

    // Check for common newsletter subjects
    let subject_regex =
        Regex::new(r"(?i)Subject:.*?(newsletter|digest|updates|weekly|daily|monthly|bulletin)")
            .unwrap();
    if subject_regex.is_match(headers) {
        trace!("Found newsletter keyword in Subject: header");
        return true;
    }

    trace!("No newsletter indicators found");
    false
}

fn check_subject_patterns(subject: &str, rules: &[SubjectRule]) -> Option<String> {
    for rule in rules {
        match Regex::new(&rule.pattern) {
            Ok(re) => {
                if re.is_match(subject) {
                    let pattern_desc = if let Some(desc) = &rule.description {
                        format!("{} ({})", rule.pattern, desc)
                    } else {
                        rule.pattern.clone()
                    };

                    trace!("Subject matched pattern: {}", pattern_desc);
                    return Some(pattern_desc);
                }
            }
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", rule.pattern, e);
            }
        }
    }
    None
}

fn check_sender_patterns(sender: &str, rules: &[SenderRule]) -> Option<String> {
    for rule in rules {
        match Regex::new(&rule.pattern) {
            Ok(re) => {
                if re.is_match(sender) {
                    let pattern_desc = if let Some(desc) = &rule.description {
                        format!("{} ({})", rule.pattern, desc)
                    } else {
                        rule.pattern.clone()
                    };

                    trace!("Sender matched pattern: {}", pattern_desc);
                    return Some(pattern_desc);
                }
            }
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", rule.pattern, e);
            }
        }
    }
    None
}
