extern crate clap;
extern crate imap;
extern crate native_tls;
extern crate regex;

use clap::{App, Arg};
use imap::Session;
use native_tls::TlsStream;
use regex::Regex;
use std::env;
use std::net::TcpStream;
use std::process;

fn main() {
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

    // Get environment variables
    let password = match env::var("EMAIL_PASSWORD") {
        Ok(val) => val,
        Err(_) => {
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

    // Connect to the server
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
                println!(
                    "Successfully moved {} newsletter messages to {}",
                    moved_count, target_folder
                );
            } else {
                println!("No newsletter messages found to move");
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
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
    let messages = session.fetch("1:*", "(ENVELOPE BODY[HEADER.FIELDS (LIST-ID LIST-UNSUBSCRIBE X-MAILCHIMP-ID X-CAMPAIGN X-MAILER)])")?;

    let mut newsletter_ids = Vec::new();

    // Process messages
    for message in messages.iter() {
        let uid = message.uid.unwrap_or(0);
        if uid == 0 {
            continue;
        }

        // Check headers for newsletter indicators
        if let Some(body) = message.body() {
            let headers = std::str::from_utf8(body)?;

            if is_newsletter(headers) {
                newsletter_ids.push(uid.to_string());
            }
        }
    }

    let moved_count = newsletter_ids.len();

    // Move identified newsletters if any were found
    if !newsletter_ids.is_empty() {
        let uid_set = newsletter_ids.join(",");
        session.mv(&uid_set, target_folder)?;
    }

    // Logout
    session.logout()?;

    Ok(moved_count)
}

fn is_newsletter(headers: &str) -> bool {
    // Check for common newsletter headers
    if headers.contains("List-ID:")
        || headers.contains("List-Unsubscribe:")
        || headers.contains("X-Mailchimp-ID:")
        || headers.contains("X-Campaign")
    {
        return true;
    }

    // Check for common newsletter senders
    let sender_regex =
        Regex::new(r"(?i)From:.*?(newsletter|digest|updates|weekly|daily|monthly|bulletin)")
            .unwrap();
    if sender_regex.is_match(headers) {
        return true;
    }

    // Check for common newsletter subjects
    let subject_regex =
        Regex::new(r"(?i)Subject:.*?(newsletter|digest|updates|weekly|daily|monthly|bulletin)")
            .unwrap();
    if subject_regex.is_match(headers) {
        return true;
    }

    false
}
