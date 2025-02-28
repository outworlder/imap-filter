// imap_client.rs
use console::style;
use imap::Session;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, error, trace, warn};
use native_tls::TlsStream;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::TcpStream;

// Define a struct to hold the necessary information for an IMAP client
pub struct ImapClient {
    // The server address as a string
    server: String,
    // The port number as a u16
    port: u16,
    // The username for the IMAP server as a string
    username: String,
    // The password for the IMAP server as a string
    password: String,
}
pub struct Message {
    pub uid: u32,
    pub subject: String,
    pub sender: String,
    pub headers: String,
    pub body: Option<String>,
}

impl ImapClient {
    pub fn new(server: &str, port: u16, username: &str, password: &str) -> Self {
        ImapClient {
            server: server.to_string(),
            port,
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn connect(&self) -> Result<Session<TlsStream<TcpStream>>, Box<dyn std::error::Error>> {
        // Setup TLS
        debug!("Setting up TLS connection");
        let tls = native_tls::TlsConnector::builder().build()?;

        // Connect to the server
        debug!("Connecting to IMAP server {}:{}", self.server, self.port);
        let client = imap::connect(
            (self.server.as_str(), self.port),
            self.server.as_str(),
            &tls,
        )?;

        // Login
        debug!("Logging in as user: {}", self.username);
        match client.login(&self.username, &self.password) {
            Ok(session) => {
                debug!("Login successful");
                Ok(session)
            }
            Err((err, _client)) => {
                error!("Login failed: {}", err);
                Err(Box::new(err))
            }
        }
    }

    pub fn get_folders(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut session = self.connect()?;

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

    pub fn create_folders(&self, folders: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        let mut session = self.connect()?;
        let available_folders = self.get_folders()?;

        for folder in folders {
            if !available_folders.contains(folder) {
                debug!("Creating folder: {}", folder);
                session.create(folder)?;
                println!("Created folder: {}", folder);
            }
        }

        session.logout()?;
        Ok(())
    }

    pub fn fetch_messages(&self, folder: &str) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
        let mut session = self.connect()?;

        // Select the source mailbox
        session.select(folder)?;

        // Search for all messages in reverse order (newest first)
        let messages = session.fetch("1:*", "(UID ENVELOPE BODY.PEEK[HEADER.FIELDS (LIST-ID LIST-UNSUBSCRIBE X-MAILCHIMP-ID X-CAMPAIGN X-MAILER)])")?;

        let total_messages = messages.iter().count();
        println!("\nScanning {} messages for processing...", total_messages);

        // Create a nice progress bar
        let progress_bar = ProgressBar::new(total_messages as u64);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:50.cyan/blue}] {pos}/{len} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );

        // Collect messages in a vector and sort by UID in descending order (newest first)
        let mut result = Vec::new();
        for (i, message) in messages.iter().enumerate() {
            // Update progress bar
            progress_bar.set_position(i as u64 + 1);

            let uid = message.uid.unwrap_or(0);
            if uid == 0 {
                warn!("Message has UUID 0");
                continue;
            }

            // Parse message data
            let mut subject = String::new();
            let mut sender = String::new();
            let mut headers = String::new();

            // Extract headers
            if let Some(body) = message.body().or_else(|| message.text()) {
                headers = match std::str::from_utf8(body) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::from_utf8_lossy(body).to_string(),
                };
            }

            // Extract subject and sender from envelope
            if let Some(envelope) = message.envelope() {
                // Get subject
                if let Some(subject_bytes) = envelope.subject {
                    subject = match std::str::from_utf8(&subject_bytes) {
                        Ok(s) => s.to_string(),
                        Err(_) => String::from_utf8_lossy(&subject_bytes).to_string(),
                    };
                }

                // Get sender
                if let Some(from_addresses) = &envelope.from {
                    for address in from_addresses {
                        // Build sender string from address components
                        let mut s = String::new();

                        // Add name if available
                        if let Some(name_bytes) = &address.name {
                            match std::str::from_utf8(name_bytes) {
                                Ok(name) => {
                                    s.push_str(name);
                                    s.push_str(" ");
                                }
                                Err(_) => {
                                    let name = String::from_utf8_lossy(name_bytes);
                                    s.push_str(&name);
                                    s.push_str(" ");
                                }
                            }
                        }

                        // Add email address
                        s.push_str("<");

                        // Add mailbox (username) part
                        if let Some(mailbox_bytes) = &address.mailbox {
                            match std::str::from_utf8(mailbox_bytes) {
                                Ok(mailbox) => {
                                    s.push_str(mailbox);
                                }
                                Err(_) => {
                                    let mailbox = String::from_utf8_lossy(mailbox_bytes);
                                    s.push_str(&mailbox);
                                }
                            }
                        }

                        // Add @ symbol if we have both mailbox and host
                        if address.mailbox.is_some() && address.host.is_some() {
                            s.push_str("@");
                        }

                        // Add host (domain) part
                        if let Some(host_bytes) = &address.host {
                            match std::str::from_utf8(host_bytes) {
                                Ok(host) => {
                                    s.push_str(host);
                                }
                                Err(_) => {
                                    let host = String::from_utf8_lossy(host_bytes);
                                    s.push_str(&host);
                                }
                            }
                        }

                        s.push_str(">");
                        sender = s;
                        break; // Just use the first sender
                    }
                }
            }

            result.push(Message {
                uid,
                subject,
                sender,
                headers,
                body: None, // We're not fetching the full body for now
            });
        }

        // Sort messages by UID in descending order (newest first)
        result.sort_by(|a, b| b.uid.cmp(&a.uid));

        // Finish the progress bar
        progress_bar.finish_with_message(format!("Scanned {} messages", total_messages));

        session.logout()?;
        Ok(result)
    }

    pub fn move_messages(
        &self,
        source_folder: &str,
        messages_by_folder: &HashMap<String, Vec<String>>,
    ) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
        let mut session = self.connect()?;
        session.select(source_folder)?;

        let mut moved_counts: HashMap<String, usize> = HashMap::new();
        let total_messages: usize = messages_by_folder.values().map(|v| v.len()).sum();

        if total_messages > 0 {
            println!(
                "\nMoving {} messages to their target folders...",
                total_messages
            );

            // Create a multi-progress bar for all folders
            let multi_progress = MultiProgress::new();

            // Create a hashmap to store progress bars for each folder
            let mut progress_bars = HashMap::new();

            // Initialize progress bars for each folder
            for (target_folder, uids) in messages_by_folder {
                let folder_count = uids.len();

                // Create a progress bar for this folder
                let pb = multi_progress.add(ProgressBar::new(folder_count as u64));
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template(&format!("{}{{spinner:.green}} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{pos}}/{{len}} ({{eta}})",
                            style(format!("{}: ", target_folder)).bold().cyan()))
                        .unwrap()
                        .progress_chars("█▓▒░")
                );
                pb.set_message(format!("Moving to '{}'", target_folder));

                // Store the progress bar
                progress_bars.insert(target_folder.clone(), pb);

                // Set initial moved count for this folder
                moved_counts.insert(target_folder.clone(), 0);
            }

            // Process each folder
            for (target_folder, uids) in messages_by_folder {
                let folder_count = uids.len();
                let pb = progress_bars.get(target_folder).unwrap();

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
                            pb.set_position(moved as u64);
                        }
                        Err(e) => {
                            pb.suspend(|| {
                                eprintln!("\nError moving messages {}: {}", uid_batch, e);
                            });

                            // Try moving individual messages to identify which ones are problematic
                            for uid in batch {
                                match session.uid_mv(uid, target_folder) {
                                    Ok(_) => {
                                        moved += 1;
                                        *moved_counts.get_mut(target_folder).unwrap() += 1;
                                        pb.set_position(moved as u64);
                                    }
                                    Err(e) => {
                                        pb.suspend(|| {
                                            eprintln!(
                                                "Failed to move message with UID {}: {}",
                                                uid, e
                                            );
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Mark this progress bar as finished
                pb.finish_with_message(format!("Moved {} messages to '{}'", moved, target_folder));
            }
        }

        session.logout()?;
        Ok(moved_counts)
    }
}
