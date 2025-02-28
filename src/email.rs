// email.rs
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::any::Any;

use crate::filter::{FilterEngine, MatchResult, HybridFilter};
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

        info!("Analyzing {} messages for classification", total_messages);
        println!("\n{}", style(format!("Scanning {} messages for processing...", total_messages)).cyan().bold());

        // Check if we're using hybrid filtering
        if let Some(hybrid_filter) = (&*self.filter).as_any().downcast_ref::<HybridFilter>() {
            // First pass: Rule-based filtering
            println!("\n{}", style(format!("Processing {} messages with rules...", total_messages)).cyan().bold());
            
            let progress_bar = ProgressBar::new(total_messages as u64);
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:50.green/white}] {pos}/{len} messages analyzed with rules ({eta})")
                    .unwrap()
                    .progress_chars("█▓▒░")
            );

            let mut rule_matches = Vec::new();
            let mut unmatched = Vec::new();

            // Process each message with rules and update progress
            for (i, message) in messages.iter().enumerate() {
                if let Some(result) = hybrid_filter.rule_filter.classify_message(message) {
                    debug!("Message matched rule-based filter: {}", result.reason);
                    rule_matches.push((message, result));
                } else {
                    unmatched.push(message);
                }
                progress_bar.set_position(i as u64 + 1);
            }

            progress_bar.finish_with_message(format!(
                "Rule analysis complete: {} of {} messages matched rules",
                rule_matches.len(),
                total_messages
            ));

            // Move rule-matched messages first
            if !rule_matches.is_empty() {
                println!("\n{}", style("MOVING RULE-MATCHED MESSAGES:").yellow().bold());

                let mut messages_by_folder: HashMap<String, Vec<String>> = HashMap::new();
                for (_, result) in &rule_matches {
                    messages_by_folder
                        .entry(result.target_folder.clone())
                        .or_insert_with(Vec::new)
                        .push(result.uid.clone());
                }

                // Move messages with progress bar for each folder
                for (folder, uids) in &messages_by_folder {
                    println!("\n\t{} {} to '{}'", 
                        style("⟳ Moving").cyan(),
                        style(format!("{} {}", uids.len(), if uids.len() > 1 { "messages" } else { "message" })).cyan(),
                        style(folder).green()
                    );

                    let move_progress = ProgressBar::new(uids.len() as u64);
                    move_progress.set_style(
                        ProgressStyle::default_bar()
                            .template("{spinner:.green} [{elapsed_precise}] [{bar:50.green/white}] {pos}/{len} messages moved ({eta})")
                            .unwrap()
                            .progress_chars("█▓▒░")
                    );

                    let mut single_folder_map = HashMap::new();
                    single_folder_map.insert(folder.clone(), uids.clone());
                    imap_client.move_messages(source_folder, &single_folder_map)?;
                    move_progress.finish();
                }

                println!("\t{}", style("✓ Rule-matched messages moved successfully").green().bold());
            }

            // Second pass: AI-based filtering for unmatched messages
            if !unmatched.is_empty() {
                println!("\n{}", style(format!("Processing {} unmatched messages with AI...", unmatched.len())).cyan().bold());
                
                let ai_progress = ProgressBar::new(unmatched.len() as u64);
                ai_progress.set_style(
                    ProgressStyle::default_bar()
                        .template("{spinner:.blue} [{elapsed_precise}] [{bar:50.blue/white}] {pos}/{len} messages analyzed with AI ({eta})")
                        .unwrap()
                        .progress_chars("█▓▒░")
                );

                let mut ai_matches: Vec<MatchResult> = Vec::new();
                for (i, message) in unmatched.iter().enumerate() {
                    if let Some(result) = hybrid_filter.ai_filter.classify_message(message) {
                        ai_matches.push(result);
                    }
                    ai_progress.set_position(i as u64 + 1);
                }

                ai_progress.finish_with_message(format!(
                    "AI analysis complete: {} matches found",
                    ai_matches.len()
                ));

                // Move AI-matched messages
                if !ai_matches.is_empty() {
                    println!("\n{}", style("MOVING AI-MATCHED MESSAGES:").yellow().bold());

                    let mut messages_by_folder: HashMap<String, Vec<String>> = HashMap::new();
                    for result in &ai_matches {
                        messages_by_folder
                            .entry(result.target_folder.clone())
                            .or_insert_with(Vec::new)
                            .push(result.uid.clone());
                    }

                    // Move messages with progress bar for each folder
                    for (folder, uids) in &messages_by_folder {
                        println!("\n\t{} {} to '{}'", 
                            style("⟳ Moving").cyan(),
                            style(format!("{} {}", uids.len(), if uids.len() > 1 { "messages" } else { "message" })).cyan(),
                            style(folder).green()
                        );

                        let move_progress = ProgressBar::new(uids.len() as u64);
                        move_progress.set_style(
                            ProgressStyle::default_bar()
                                .template("{spinner:.blue} [{elapsed_precise}] [{bar:50.blue/white}] {pos}/{len} messages moved ({eta})")
                                .unwrap()
                                .progress_chars("█▓▒░")
                        );

                        let mut single_folder_map = HashMap::new();
                        single_folder_map.insert(folder.clone(), uids.clone());
                        imap_client.move_messages(source_folder, &single_folder_map)?;
                        move_progress.finish();
                    }

                    println!("\t{}", style("✓ AI-matched messages moved successfully").green().bold());
                }

                // Return combined results
                let mut total_moved: HashMap<String, usize> = HashMap::new();
                for (_, result) in rule_matches {
                    *total_moved.entry(result.target_folder).or_insert(0) += 1;
                }
                for result in ai_matches {
                    *total_moved.entry(result.target_folder).or_insert(0) += 1;
                }
                Ok(total_moved)
            } else {
                // Only rule-matched messages
                let mut total_moved: HashMap<String, usize> = HashMap::new();
                for (_, result) in rule_matches {
                    *total_moved.entry(result.target_folder).or_insert(0) += 1;
                }
                Ok(total_moved)
            }
        } else {
            // Non-hybrid filtering - process all messages with the single filter
            let progress_bar = ProgressBar::new(total_messages as u64);
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:50.green/white}] {pos}/{len} messages analyzed ({eta})")
                    .unwrap()
                    .progress_chars("█▓▒░")
            );

            let mut matched_messages: Vec<MatchResult> = Vec::new();
            for (i, message) in messages.iter().enumerate() {
                if let Some(result) = self.filter.classify_message(message) {
                    matched_messages.push(result);
                }
                progress_bar.set_position(i as u64 + 1);
            }

            progress_bar.finish_with_message(format!(
                "Analysis complete: {} of {} messages matched filters",
                matched_messages.len(),
                total_messages
            ));

            // Move matched messages
            if !matched_messages.is_empty() {
                println!("\n{}", style("MOVING MESSAGES:").yellow().bold());
                println!("\t{}", style("⟳ Moving matched messages...").cyan());

                let mut messages_by_folder: HashMap<String, Vec<String>> = HashMap::new();
                for result in &matched_messages {
                    messages_by_folder
                        .entry(result.target_folder.clone())
                        .or_insert_with(Vec::new)
                        .push(result.uid.clone());
                }

                // Display match info
                for (folder, uids) in &messages_by_folder {
                    println!("\t  → {} to '{}'", 
                        style(format!("{} {}", uids.len(), if uids.len() > 1 { "messages" } else { "message" })).cyan(),
                        style(folder).green()
                    );
                }

                // Move messages
                imap_client.move_messages(source_folder, &messages_by_folder)?;
                println!("\t{}", style("✓ Messages moved successfully").green().bold());

                // Return results
                let mut total_moved: HashMap<String, usize> = HashMap::new();
                for result in matched_messages {
                    *total_moved.entry(result.target_folder).or_insert(0) += 1;
                }
                Ok(total_moved)
            } else {
                Ok(HashMap::new())
            }
        }
    }
}
