// email.rs
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info};
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
        let mut messages = imap_client.fetch_messages(source_folder)?;
        
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
        if total_matched > 0 {
            println!("\nFound {} messages to move:", total_matched);

            let mut folder_counts: HashMap<String, usize> = HashMap::new();
            for matched in &matched_messages {
                let count = folder_counts
                    .entry(matched.target_folder.clone())
                    .or_insert(0);
                *count += 1;
            }

            for (folder, count) in &folder_counts {
                println!("  - {} to '{}' folder", count, folder);
            }

            if matched_messages.len() <= 20 {
                println!("\nMatched messages:");
                for (i, matched) in matched_messages.iter().enumerate() {
                    println!(
                        "  {}. UID {}: {} (Reason: {})",
                        i + 1,
                        matched.uid,
                        matched.target_folder,
                        matched.reason
                    );
                }
            }
        } else {
            println!("No messages matched the filtering criteria");
            return Ok(HashMap::new());
        }

        // Move messages
        imap_client.move_messages(source_folder, &messages_by_folder)
    }
}
