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
use std::collections::HashMap;
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
    folder: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SenderRule {
    pattern: String,
    description: Option<String>,
    folder: Option<String>,
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
    info!("Default target folder: {}", target_folder);
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
    println!("Default target folder: {}", target_folder);
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
            let folder_info = if let Some(folder) = &rule.folder {
                format!(" -> {}", folder)
            } else {
                "".to_string()
            };

            if let Some(desc) = &rule.description {
                println!("  {}. {} - {}{}", i + 1, rule.pattern, desc, folder_info);
            } else {
                println!("  {}. {}{}", i + 1, rule.pattern, folder_info);
            }
        }

        if !cfg.sender_rules.is_empty() {
            println!("\nConfigured sender patterns:");
            for (i, rule) in cfg.sender_rules.iter().enumerate() {
                let folder_info = if let Some(folder) = &rule.folder {
                    format!(" -> {}", folder)
                } else {
                    "".to_string()
                };

                if let Some(desc) = &rule.description {
                    println!("  {}. {} - {}{}", i + 1, rule.pattern, desc, folder_info);
                } else {
                    println!("  {}. {}{}", i + 1, rule.pattern, folder_info);
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

    // Collect all unique target folders
    let mut unique_folders = vec![target_folder.to_string()];
    if let Some(cfg) = &config {
        for rule in &cfg.subject_rules {
            if let Some(folder) = &rule.folder {
                if !unique_folders.contains(&folder.to_string()) {
                    unique_folders.push(folder.to_string());
                }
            }
        }
        for rule in &cfg.sender_rules {
            if let Some(folder) = &rule.folder {
                if !unique_folders.contains(&folder.to_string()) {
                    unique_folders.push(folder.to_string());
                }
            }
        }
    }

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
        Ok(moved_counts) => {
            let total_moved: usize = moved_counts.values().sum();

            if total_moved > 0 {
                info!("Successfully moved {} messages", total_moved);
                println!("\nSuccessfully moved {} messages:", total_moved);

                for (folder, count) in &moved_counts {
                    if *count > 0 {
                        println!("  - {} to '{}'", count, folder);
                    }
                }
            } else {
                info!("No messages found to move");
                println!("No messages found to move");
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

#[derive(Debug)]
struct MatchInfo {
    uid: String,
    reason: String,
    target_folder: String,
}

fn connect_and_process(
    server: &str,
    port: u16,
    username: &str,
    password: &str,
    source_folder: &str,
    default_target_folder: &str,
    config: Option<&Config>,
) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    // Setup TLS
    let tls = native_tls::TlsConnector::builder().build()?;

    // Connect to the server
    let client = imap::connect((server, port), server, &tls)?;

    // Login - handle the error manually since it returns a tuple
    let mut session = match client.login(username, password) {
        Ok(session) => session,
        Err((err, _client)) => return Err(Box::new(err)),
    };

    // Get all available folders
    let folders = session.list(None, Some("*"))?;
    let available_folders: Vec<String> = folders.iter().map(|f| f.name().to_string()).collect();

    // Collect all potentially needed target folders
    let mut needed_folders = vec![default_target_folder.to_string()];
    if let Some(cfg) = config {
        for rule in &cfg.subject_rules {
            if let Some(folder) = &rule.folder {
                if !needed_folders.contains(folder) {
                    needed_folders.push(folder.to_string());
                }
            }
        }
        for rule in &cfg.sender_rules {
            if let Some(folder) = &rule.folder {
                if !needed_folders.contains(folder) {
                    needed_folders.push(folder.to_string());
                }
            }
        }
    }

    // Create any missing folders
    for folder in &needed_folders {
        if !available_folders.contains(folder) {
            info!("Creating folder: {}", folder);
            session.create(folder)?;
            println!("Created folder: {}", folder);
        }
    }

    // Select the source mailbox
    session.select(source_folder)?;

    // Search for all messages
    let messages = session.fetch("1:*", "(UID ENVELOPE BODY.PEEK[HEADER.FIELDS (LIST-ID LIST-UNSUBSCRIBE X-MAILCHIMP-ID X-CAMPAIGN X-MAILER)])")?;

    // First pass: identify newsletters
    println!("\nScanning messages for newsletters and pattern matches...");
    let total_messages = messages.iter().count();
    let bar_width = 50;

    let mut matched_messages = Vec::new();

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
        let mut target_folder = default_target_folder.to_string();

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
                    if let Some((pattern_match, folder)) =
                        check_subject_patterns(&subject_str, &config.unwrap().subject_rules)
                    {
                        matched = true;
                        reason = format!("Subject pattern: {}", pattern_match);

                        // Use rule-specific folder if provided
                        if let Some(rule_folder) = folder {
                            target_folder = rule_folder.to_string();
                        }
                    }
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
                        if let Some((pattern_match, folder)) =
                            check_sender_patterns(&sender, &config.unwrap().sender_rules)
                        {
                            matched = true;
                            reason = format!("Sender pattern: {}", pattern_match);

                            // Use rule-specific folder if provided
                            if let Some(rule_folder) = folder {
                                target_folder = rule_folder.to_string();
                            }

                            break; // No need to check other addresses
                        }
                    }
                }
            }
        }

        // Add to matched list if matched
        if matched {
            matched_messages.push(MatchInfo {
                uid: uid.to_string(),
                reason,
                target_folder,
            });
        }
    }

    // Clear the progress line
    println!(
        "\r[{}] {}/{}",
        "#".repeat(bar_width),
        total_messages,
        total_messages
    );

    // Group messages by target folder
    let mut messages_by_folder: HashMap<String, Vec<String>> = HashMap::new();
    for matched in &matched_messages {
        messages_by_folder
            .entry(matched.target_folder.clone())
            .or_insert_with(Vec::new)
            .push(matched.uid.clone());
    }

    let total_matched = matched_messages.len();

    // Move messages by folder
    let mut moved_counts: HashMap<String, usize> = HashMap::new();
    let mut failed_count = 0;

    if !matched_messages.is_empty() {
        println!(
            "\nMoving {} messages to their target folders...",
            total_matched
        );

        for (target_folder, uids) in &messages_by_folder {
            let folder_count = uids.len();
            println!("Moving {} messages to '{}'...", folder_count, target_folder);

            // Set initial moved count for this folder
            moved_counts.insert(target_folder.clone(), 0);

            // Move messages in batches to show progress
            let batch_size = 10.max(folder_count / 20).min(folder_count); // At least 10, at most all, aim for ~20 batches
            let mut moved = 0;

            while moved < folder_count {
                let end = (moved + batch_size).min(folder_count);
                let batch = &uids[moved..end];
                let uid_batch = batch.join(",");

                match session.uid_mv(&uid_batch, target_folder) {
                    Ok(_) => {
                        moved += batch.len();
                        *moved_counts.get_mut(target_folder).unwrap() += batch.len();
                    }
                    Err(e) => {
                        eprintln!("\nError moving messages {}: {}", uid_batch, e);
                        // Try moving individual messages to identify which ones are problematic
                        for uid in batch {
                            match session.uid_mv(uid, target_folder) {
                                Ok(_) => {
                                    moved += 1;
                                    *moved_counts.get_mut(target_folder).unwrap() += 1;
                                }
                                Err(e) => {
                                    eprintln!("Failed to move message with UID {}: {}", uid, e);
                                    failed_count += 1;
                                }
                            }
                        }
                    }
                }

                // Update progress bar
                let progress = (moved as f32 / folder_count as f32 * bar_width as f32) as usize;
                print!(
                    "\r[{:<50}] {}/{}",
                    "#".repeat(progress),
                    moved,
                    folder_count
                );
                io::stdout().flush()?;
            }

            println!(); // Final newline after progress bar
        }

        // Report failures if any
        if failed_count > 0 {
            eprintln!("\nWarning: Failed to move {} messages", failed_count);
        }
    }

    // Logout
    session.logout()?;

    Ok(moved_counts)
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

fn check_subject_patterns(
    subject: &str,
    rules: &[SubjectRule],
) -> Option<(String, Option<String>)> {
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
                    return Some((pattern_desc, rule.folder.clone()));
                }
            }
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", rule.pattern, e);
            }
        }
    }
    None
}

fn check_sender_patterns(sender: &str, rules: &[SenderRule]) -> Option<(String, Option<String>)> {
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
                    return Some((pattern_desc, rule.folder.clone()));
                }
            }
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", rule.pattern, e);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper function to create a temporary config file with specific content
    fn create_temp_config(content: &str) -> (NamedTempFile, String) {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        let path = file.path().to_str().unwrap().to_string();
        (file, path)
    }

    #[test]
    fn test_read_config() {
        let config_content = r#"
            [[subject_rules]]
            pattern = "Newsletter"
            description = "Test newsletter"
            folder = "TestFolder"

            [[subject_rules]]
            pattern = "Update"
            description = "Test update"

            [[sender_rules]]
            pattern = "test@example.com"
            description = "Test sender"
            folder = "SenderFolder"
        "#;

        let (_file, path) = create_temp_config(config_content);

        let config = read_config(&path).unwrap();

        assert_eq!(config.subject_rules.len(), 2);
        assert_eq!(config.sender_rules.len(), 1);

        // Test first subject rule
        assert_eq!(config.subject_rules[0].pattern, "Newsletter");
        assert_eq!(
            config.subject_rules[0].description,
            Some("Test newsletter".to_string())
        );
        assert_eq!(
            config.subject_rules[0].folder,
            Some("TestFolder".to_string())
        );

        // Test second subject rule (no folder)
        assert_eq!(config.subject_rules[1].pattern, "Update");
        assert_eq!(
            config.subject_rules[1].description,
            Some("Test update".to_string())
        );
        assert_eq!(config.subject_rules[1].folder, None);

        // Test sender rule
        assert_eq!(config.sender_rules[0].pattern, "test@example.com");
        assert_eq!(
            config.sender_rules[0].description,
            Some("Test sender".to_string())
        );
        assert_eq!(
            config.sender_rules[0].folder,
            Some("SenderFolder".to_string())
        );
    }

    #[test]
    fn test_is_newsletter() {
        // Test positive cases
        assert!(is_newsletter("List-ID: <abcdef.list-id.example.com>"));
        assert!(is_newsletter(
            "List-Unsubscribe: <https://example.com/unsubscribe>"
        ));
        assert!(is_newsletter("X-Mailchimp-ID: abc123"));
        assert!(is_newsletter("X-Campaign: newsletter"));
        assert!(is_newsletter("From: Company Newsletter <news@example.com>"));
        assert!(is_newsletter("Subject: Your Weekly Digest"));

        // Test negative cases
        assert!(!is_newsletter("From: John Doe <john@example.com>"));
        assert!(!is_newsletter("Subject: Hello friend"));
        assert!(!is_newsletter("Content-Type: text/plain"));
    }

    #[test]
    fn test_check_subject_patterns() {
        let rules = vec![
            SubjectRule {
                pattern: r"(?i)newsletter".to_string(),
                description: Some("Company newsletters".to_string()),
                folder: Some("Newsletters".to_string()),
            },
            SubjectRule {
                pattern: r"(?i)invoice|receipt".to_string(),
                description: Some("Financial emails".to_string()),
                folder: Some("Financial".to_string()),
            },
            SubjectRule {
                pattern: r"(?i)update".to_string(),
                description: Some("Updates".to_string()),
                folder: None,
            },
        ];

        // Test matching with folder
        let result = check_subject_patterns("Your Weekly Newsletter", &rules);
        assert!(result.is_some());
        let (pattern, folder) = result.unwrap();
        assert!(pattern.contains("newsletter"));
        assert_eq!(folder, Some("Newsletters".to_string()));

        // Test matching with different folder
        let result = check_subject_patterns("Invoice #12345", &rules);
        assert!(result.is_some());
        let (pattern, folder) = result.unwrap();
        assert!(pattern.contains("invoice"));
        assert_eq!(folder, Some("Financial".to_string()));

        // Test matching without folder
        let result = check_subject_patterns("Security Update", &rules);
        assert!(result.is_some());
        let (pattern, folder) = result.unwrap();
        assert!(pattern.contains("update"));
        assert_eq!(folder, None);

        // Test no match
        let result = check_subject_patterns("Hello World", &rules);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_sender_patterns() {
        let rules = vec![
            SenderRule {
                pattern: r"noreply@example\.com".to_string(),
                description: Some("Example notifications".to_string()),
                folder: Some("Notifications".to_string()),
            },
            SenderRule {
                pattern: r".*@newsletter\.com".to_string(),
                description: Some("Newsletter service".to_string()),
                folder: Some("Newsletters".to_string()),
            },
            SenderRule {
                pattern: r"support@.*\.com".to_string(),
                description: Some("Support emails".to_string()),
                folder: None,
            },
        ];

        // Test matching with folder
        let result = check_sender_patterns("Company <noreply@example.com>", &rules);
        assert!(result.is_some());
        let (pattern, folder) = result.unwrap();
        assert!(pattern.contains("noreply@example"));
        assert_eq!(folder, Some("Notifications".to_string()));

        // Test matching with different folder
        let result = check_sender_patterns("News <news@newsletter.com>", &rules);
        assert!(result.is_some());
        let (pattern, folder) = result.unwrap();
        assert!(pattern.contains("@newsletter"));
        assert_eq!(folder, Some("Newsletters".to_string()));

        // Test matching without folder
        let result = check_sender_patterns("Support <support@company.com>", &rules);
        assert!(result.is_some());
        let (pattern, folder) = result.unwrap();
        assert!(pattern.contains("support@"));
        assert_eq!(folder, None);

        // Test no match
        let result = check_sender_patterns("John Doe <john@personal.net>", &rules);
        assert!(result.is_none());
    }

    // Mock IMAP session for testing
    struct MockSession {
        folders: Vec<String>,
        emails: Vec<MockEmail>,
        moved_emails: HashMap<String, Vec<String>>,
    }

    struct MockEmail {
        uid: u32,
        subject: String,
        sender: String,
        headers: String,
    }

    impl MockSession {
        fn new() -> Self {
            MockSession {
                folders: vec!["INBOX".to_string(), "Archive".to_string()],
                emails: Vec::new(),
                moved_emails: HashMap::new(),
            }
        }

        fn add_email(&mut self, uid: u32, subject: &str, sender: &str, is_newsletter: bool) {
            let mut headers = format!("Subject: {}\nFrom: {}\n", subject, sender);
            if is_newsletter {
                headers.push_str("List-ID: <list.example.com>\n");
            }

            self.emails.push(MockEmail {
                uid,
                subject: subject.to_string(),
                sender: sender.to_string(),
                headers,
            });
        }

        fn create_folder(&mut self, folder: &str) -> Result<(), String> {
            if !self.folders.contains(&folder.to_string()) {
                self.folders.push(folder.to_string());
            }
            Ok(())
        }

        fn move_email(&mut self, uid: &str, target_folder: &str) -> Result<(), String> {
            // Verify UID exists
            let uid_num: u32 = uid.parse().map_err(|_| "Invalid UID".to_string())?;
            if !self.emails.iter().any(|e| e.uid == uid_num) {
                return Err(format!("Email with UID {} not found", uid));
            }

            // Verify folder exists
            if !self.folders.contains(&target_folder.to_string()) {
                return Err(format!("Folder {} does not exist", target_folder));
            }

            // Record the move operation
            self.moved_emails
                .entry(target_folder.to_string())
                .or_insert_with(Vec::new)
                .push(uid.to_string());

            Ok(())
        }
    }

    #[test]
    fn test_email_processing_logic() {
        // Create mock session
        let mut session = MockSession::new();
        
        // Add test emails
        session.add_email(1, "Regular email", "person@example.com", false);
        session.add_email(2, "Weekly Newsletter", "news@company.com", true);
        session.add_email(3, "Your Invoice #123", "billing@example.com", false);
        session.add_email(4, "Product Update", "updates@example.com", true);
        
        // Create folders
        session.create_folder("Newsletters").unwrap();
        session.create_folder("Financial").unwrap();
        
        // Define rules
        let config = Config {
            subject_rules: vec![
                SubjectRule {
                    pattern: r"(?i)newsletter".to_string(),
                    description: Some("Newsletters".to_string()),
                    folder: Some("Newsletters".to_string()),
                },
                SubjectRule {
                    pattern: r"(?i)invoice".to_string(),
                    description: Some("Invoices".to_string()),
                    folder: Some("Financial".to_string()),
                },
                SubjectRule {
                    pattern: r"(?i)update".to_string(),
                    description: None,
                    folder: None,
                },
            ],
            sender_rules: vec![],
        };
        
        // Process each email manually to simulate the core logic
        let default_target = "Archive";
        let mut moved_counts: HashMap<String, usize> = HashMap::new();
        
        // First, collect the emails we need to process and their target folders
        let moves_to_perform: Vec<(u32, String)> = session.emails.iter()
            .filter_map(|email| {
                let mut matched = false;
                let mut target_folder = default_target.to_string();
                
                // Check if it's a newsletter based on headers
                if is_newsletter(&email.headers) {
                    matched = true;
                }
                
                // Check subject patterns
                if !matched {
                    if let Some((_, folder)) = check_subject_patterns(&email.subject, &config.subject_rules) {
                        matched = true;
                        if let Some(rule_folder) = folder {
                            target_folder = rule_folder;
                        }
                    }
                }
                
                if matched {
                    Some((email.uid, target_folder))
                } else {
                    None
                }
            })
            .collect();
        
        // Now process the moves separately from the iteration
        for (uid, target_folder) in moves_to_perform {
            let uid_str = uid.to_string();
            session.move_email(&uid_str, &target_folder).unwrap();
            *moved_counts.entry(target_folder).or_insert(0) += 1;
        }
        
        // Verify results
        assert_eq!(moved_counts.get("Newsletters").unwrap_or(&0), &1);
        assert_eq!(moved_counts.get("Financial").unwrap_or(&0), &1);
        assert_eq!(moved_counts.get("Archive").unwrap_or(&0), &1); // The Update email
        
        // Verify correct emails were moved to each folder
        assert!(session.moved_emails.get("Newsletters").unwrap().contains(&"2".to_string()));
        assert!(session.moved_emails.get("Financial").unwrap().contains(&"3".to_string()));
        assert!(session.moved_emails.get("Archive").unwrap().contains(&"4".to_string()));
        
        // Verify that regular email was not moved
        let all_moved: Vec<String> = session.moved_emails.values()
            .flat_map(|v| v.clone())
            .collect();
        assert!(!all_moved.contains(&"1".to_string()));
    }

    #[test]
    fn test_nested_folders() {
        let config_content = r#"
            [[subject_rules]]
            pattern = "Newsletter"
            description = "Test newsletter"
            folder = "Newsletters.Company"

            [[sender_rules]]
            pattern = "test@example.com"
            description = "Test sender"
            folder = "Senders/Company"
        "#;

        let (_file, path) = create_temp_config(config_content);

        let config = read_config(&path).unwrap();

        // Test nested folder with dot notation
        assert_eq!(
            config.subject_rules[0].folder,
            Some("Newsletters.Company".to_string())
        );

        // Test nested folder with slash notation
        assert_eq!(
            config.sender_rules[0].folder,
            Some("Senders/Company".to_string())
        );
    }

    #[test]
    fn test_invalid_regex_patterns() {
        // Create rules with one invalid pattern
        let subject_rules = vec![
            SubjectRule {
                pattern: r"[invalid regex".to_string(), // Invalid regex
                description: None,
                folder: None,
            },
            SubjectRule {
                pattern: r"valid-pattern".to_string(), // Valid regex
                description: None,
                folder: None,
            },
        ];

        // The function should skip the invalid pattern and continue
        let result = check_subject_patterns("valid-pattern", &subject_rules);
        assert!(result.is_some());
        let (pattern, _) = result.unwrap();
        assert_eq!(pattern, "valid-pattern");

        // Test with all invalid patterns
        let invalid_rules = vec![
            SubjectRule {
                pattern: r"[invalid regex".to_string(),
                description: None,
                folder: None,
            },
            SubjectRule {
                pattern: r"(".to_string(),
                description: None,
                folder: None,
            },
        ];

        // Should return None when no valid patterns match
        let result = check_subject_patterns("test string", &invalid_rules);
        assert!(result.is_none());
    }
}
