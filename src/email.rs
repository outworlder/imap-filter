// email.rs
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::{self, Write};

use crate::filter::{FilterEngine, MatchResult};
use crate::imap_client::ImapClient;

pub struct EmailProcessor {
    filter: Box<dyn FilterEngine>,
}

impl EmailProcessor {
    pub fn new(filter: Box<dyn FilterEngine>) -> Self {
        Self { filter }
    }

    pub fn process_emails(
        &self,
        imap_client: &mut ImapClient,
        source_folder: &str,
        message_limit: Option<usize>,
    ) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
        // Ensure target folders exist
        let target_folders = self.filter.get_target_folders();
        imap_client.create_folders(&target_folders)?;

        // Fetch messages from source folder
        let result = imap_client.fetch_messages(source_folder);
        
        let mut messages = match result {
            Ok(msgs) => msgs,
            Err(e) => {
                // Check if it's the "No matching messages" error
                if e.to_string().contains("No matching messages") {
                    warn!("No messages found in folder '{}'", source_folder);
                    println!("\n{}", style("SCAN RESULTS:").yellow().bold());
                    println!("\t{} {}", 
                        style("✗ No messages found in folder").yellow(),
                        style(source_folder).yellow().bold()
                    );
                    return Ok(HashMap::new());
                } else {
                    // Propagate other errors
                    return Err(e);
                }
            }
        };
        
        // Apply message limit if specified
        if let Some(limit) = message_limit {
            if limit > 0 && limit < messages.len() {
                info!("Limiting processing to {} most recent messages", limit);
                messages.truncate(limit);
            }
        }
        
        let total_messages = messages.len();

        // First pass: identify messages to move
        info!("Analyzing {} messages for classification", total_messages);
        println!("\n{}", style(format!("Scanning {} messages for processing...", total_messages)).cyan().bold());
        let mut matched_messages: Vec<MatchResult> = Vec::new();

        // Create a nice progress bar for analysis
        let progress_bar = ProgressBar::new(total_messages as u64);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:50.green/white}] {pos}/{len} messages analyzed ({eta})")
                .unwrap()
                .progress_chars("█▓▒░")
        );

        for (i, message) in messages.iter().enumerate() {
            if let Some(result) = self.filter.classify_message(message) {
                matched_messages.push(result);
            }
            progress_bar.set_position(i as u64 + 1);
        }

        // Finish the progress bar
        progress_bar.finish_with_message(format!(
            "Analysis complete: {} of {} messages matched filters",
            matched_messages.len(),
            total_messages
        ));

        // Group messages by target folder
        let mut messages_by_folder: HashMap<String, Vec<String>> = HashMap::new();
        for matched in &matched_messages {
            messages_by_folder
                .entry(matched.target_folder.clone())
                .or_insert_with(Vec::new)
                .push(matched.uid.clone());
        }

        // Display match info
        let total_matched = matched_messages.len();
        println!("\n{}", style("SCAN RESULTS:").yellow().bold());
        
        if total_matched > 0 {
            println!("\t{} {}", 
                style(format!("✓ Found {} message{} to move:", total_matched, if total_matched > 1 { "s" } else { "" })).green().bold(),
                style("📧").cyan()
            );

            let mut folder_counts: HashMap<String, usize> = HashMap::new();
            for matched in &matched_messages {
                let count = folder_counts
                    .entry(matched.target_folder.clone())
                    .or_insert(0);
                *count += 1;
            }

            for (folder, count) in &folder_counts {
                println!("\t  → {} to '{}'", 
                    style(format!("{} {}", count, if *count > 1 { "messages" } else { "message" })).cyan(),
                    style(folder).green()
                );
            }

            if matched_messages.len() <= 20 {
                println!("\n{}", style("MATCHED EMAILS:").yellow().bold());
                for (i, matched) in matched_messages.iter().enumerate() {
                    println!(
                        "\t{}. {} {}: {} ({})",
                        style(i + 1).blue(),
                        style("UID").dim(),
                        style(&matched.uid).cyan(),
                        style(&matched.target_folder).green(),
                        style(&matched.reason).dim()
                    );
                }
            }
        } else {
            println!("\t{}", style("✗ No messages matched the filtering criteria").yellow());
            return Ok(HashMap::new());
        }

        // Move messages
        println!("\n{}", style("MOVING EMAILS:").yellow().bold());
        println!("\t{}", style("⟳ Moving messages to their target folders...").cyan());
        
        let result = imap_client.move_messages(source_folder, &messages_by_folder);
        
        if result.is_ok() {
            println!("\t{}", style("✓ All messages successfully moved").green().bold());
        }
        
        result
    }
}
