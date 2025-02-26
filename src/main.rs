extern crate clap;
extern crate env_logger;
extern crate imap;
extern crate log;
extern crate native_tls;
extern crate regex;

use log::{debug, error, info, trace, warn};
use std::io::{self, Write};

use clap::{App, Arg};
use imap::Session;
use native_tls::TlsStream;
use regex::Regex;
use std::env;
use std::net::TcpStream;
use std::process;

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

    // Print information about what the program will do
    info!("=== Email Newsletter Organizer ===");
    info!("IMAP Server: {}:{}", server, port);
    info!("Username: {}", username);
    info!("Source folder: {}", source_folder);
    info!("Target folder: {}", target_folder);
    println!("=== Email Newsletter Organizer ===");
    println!("IMAP Server: {}:{}", server, port);
    println!("Username: {}", username);
    println!("Source folder: {}", source_folder);
    println!("Target folder: {}", target_folder);

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
    let messages = session.fetch("1:*", "(UID ENVELOPE BODY.PEEK[HEADER.FIELDS (TO FROM SUBJECT LIST-ID LIST-UNSUBSCRIBE X-MAILCHIMP-ID X-CAMPAIGN X-MAILER)])")?;

    let mut newsletter_ids: Vec<String> = Vec::new();

    // First pass: identify newsletters
    println!("\nScanning messages for newsletters...");
    let total_messages = messages.iter().count();
    let bar_width = 50;

    let mut newsletter_ids = Vec::new();

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
        trace!("Checking message: {}", message.uid.unwrap_or(0));

        let uid = message.uid.unwrap_or(0);
        if uid == 0 {
            continue;
        }

        // Check headers for newsletter indicators
        if let Some(headers) = message.header() {
            let header_str = std::str::from_utf8(headers)?;
            {
                if is_newsletter(header_str) {
                    newsletter_ids.push(uid.to_string());
                }
            }
        } else {
            error!("Error fetching message body");
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
    } else if headers.contains("List-Unsubscribe:") {
        trace!("Found List-Unsubscribe header");
        return true;
    } else if headers.contains("X-Mailchimp-ID:") {
        trace!("Found X-Mailchimp-ID header");
        return true;
    } else if headers.contains("X-Campaign") {
        trace!("Found X-Campaign header");
        return true;
    } else {
        trace!("Didn't find matching headers")
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
