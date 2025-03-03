// email.rs
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::error::Error;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;

use crate::filter::{FilterEngine, MatchResult, HybridFilter, MatchSource, HybridMode};
use crate::imap_client::ImapClient;

pub struct EmailProcessor {
    filter: Box<dyn FilterEngine>,
}

impl EmailProcessor {
    pub fn new(filter: Box<dyn FilterEngine>) -> Self {
        EmailProcessor { filter }
    }

    pub fn process_emails(
        &mut self,
        imap_client: &mut ImapClient,
        source_folder: &str,
        message_limit: Option<usize>,
    ) -> Result<HashMap<String, usize>, Box<dyn Error>> {
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
        
        // Check if we're using hybrid filtering
        let is_hybrid = self.filter.as_any().is::<HybridFilter>();
        
        if is_hybrid {
            println!("\n{}", style(format!("Processing {} messages with rules first...", total_messages)).cyan().bold());
        } else {
            println!("\n{}", style(format!("Scanning {} messages for processing...", total_messages)).cyan().bold());
        }

        let progress_bar = ProgressBar::new(total_messages as u64);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template(if is_hybrid {
                    "{spinner:.green} [{elapsed_precise}] [{bar:50.green/white}] {pos}/{len} messages analyzed with rules ({eta})"
                } else {
                    "{spinner:.green} [{elapsed_precise}] [{bar:50.green/white}] {pos}/{len} messages analyzed ({eta})"
                })
                .unwrap()
                .progress_chars("█▓▒░")
        );

        let mut matched_messages: Vec<MatchResult> = Vec::new();
        let mut rule_matches = 0;
        let mut ai_matches = 0;
        let mut unmatched_messages = Vec::new();

        // First pass: Rule-based filtering
        for (i, message) in messages.iter().enumerate() {
            if let Some(result) = self.filter.classify_message(message) {
                match result.source {
                    MatchSource::Rule => {
                        rule_matches += 1;
                        debug!("Message matched rule-based filter: {}", result.reason);
                        matched_messages.push(result);
                    }
                    MatchSource::AI => {
                        // This shouldn't happen in rule phase
                        warn!("Unexpected AI match during rule phase - this may indicate a filter configuration issue");
                    }
                }
            } else {
                unmatched_messages.push(message);
            }
            progress_bar.set_position(i as u64 + 1);
        }

        progress_bar.finish_with_message(format!(
            "Rule analysis complete: {} of {} messages matched rules",
            rule_matches,
            total_messages
        ));

        // Second pass: AI-based filtering (only in hybrid mode for unmatched messages)
        if is_hybrid && !unmatched_messages.is_empty() {
            // We need to set the mode before we start processing
            if let Some(hybrid_filter) = self.filter.as_any_mut().downcast_mut::<HybridFilter>() {
                hybrid_filter.set_mode(HybridMode::AI);
                debug!("Switched to AI mode for processing {} unmatched messages", unmatched_messages.len());
            }

            println!("\n{}", style(format!("Processing {} unmatched messages with AI...", unmatched_messages.len())).cyan().bold());
            
            let ai_progress = ProgressBar::new(unmatched_messages.len() as u64);
            ai_progress.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.blue} [{elapsed_precise}] [{bar:50.blue/white}] {pos}/{len} messages analyzed with AI ({eta})")
                    .unwrap()
                    .progress_chars("█▓▒░")
            );

            for (i, message) in unmatched_messages.iter().enumerate() {
                if let Some(result) = self.filter.classify_message(message) {
                    match result.source {
                        MatchSource::AI => {
                            ai_matches += 1;
                            debug!("Message matched AI-based filter: {}", result.reason);
                            matched_messages.push(result);
                        }
                        MatchSource::Rule => {
                            // This shouldn't happen in AI phase
                            warn!("Unexpected rule match during AI phase - this may indicate a filter configuration issue");
                        }
                    }
                }
                ai_progress.set_position(i as u64 + 1);
            }

            ai_progress.finish_with_message(format!(
                "AI analysis complete: {} matches found",
                ai_matches
            ));

            // Reset back to Rules mode
            if let Some(hybrid_filter) = self.filter.as_any_mut().downcast_mut::<HybridFilter>() {
                hybrid_filter.set_mode(HybridMode::Rules);
                debug!("Reset to Rules mode after AI processing");
            }
        }

        // Move matched messages
        if !matched_messages.is_empty() {
            if is_hybrid {
                println!("\n{}", style("MOVING MATCHED MESSAGES:").yellow().bold());
                println!("\t{} {}", 
                    style(format!("✓ {} messages matched by rules", rule_matches)).green(),
                    if rule_matches > 0 { style("⚡").cyan() } else { style("").cyan() }
                );
                println!("\t{} {}", 
                    style(format!("✓ {} messages matched by AI", ai_matches)).blue(),
                    if ai_matches > 0 { style("🤖").cyan() } else { style("").cyan() }
                );
            } else {
                println!("\n{}", style("MOVING MESSAGES:").yellow().bold());
            }
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

    pub fn watch_folder(
        &mut self,
        imap_client: &mut ImapClient,
        source_folder: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Keep track of successfully moved message UIDs
        let mut moved_uids: HashSet<String> = HashSet::new();
        
        // Ensure target folders exist
        let target_folders = self.filter.get_target_folders();
        imap_client.create_folders(&target_folders)?;
        
        // Initial scan to process existing messages
        info!("Performing initial scan of existing messages");
        let initial_results = self.process_emails(imap_client, source_folder, None)?;
        if !initial_results.is_empty() {
            println!("\n{}", style("Initial scan complete:").yellow().bold());
            print_results(&initial_results);
            
            // Record UIDs of successfully moved messages from initial scan
            if let Ok(messages) = imap_client.fetch_messages(source_folder) {
                for message in messages {
                    moved_uids.insert(message.uid.to_string());
                }
            }
        }

        println!("\n{}", style("Watching for new messages...").cyan());
        
        // Continuous monitoring loop
        loop {
            // Check for new messages
            if let Ok(messages) = imap_client.fetch_messages(source_folder) {
                let mut messages_to_process = Vec::new();
                
                // Include messages that haven't been successfully moved
                for message in messages {
                    if !moved_uids.contains(&message.uid.to_string()) {
                        messages_to_process.push(message);
                    }
                }
                
                // Process messages if any found
                if !messages_to_process.is_empty() {
                    info!("Processing {} messages", messages_to_process.len());
                    println!("\n{}", style(format!("Processing {} messages...", messages_to_process.len())).cyan());
                    
                    let is_hybrid = self.filter.as_any().is::<HybridFilter>();
                    let mut matched_messages: Vec<MatchResult> = Vec::new();
                    let mut rule_matches = 0;
                    let mut ai_matches = 0;
                    let mut unmatched_messages = Vec::new();

                    // First pass: Rule-based filtering
                    for message in &messages_to_process {
                        if let Some(result) = self.filter.classify_message(message) {
                            match result.source {
                                MatchSource::Rule => {
                                    rule_matches += 1;
                                    debug!("Message matched rule-based filter: {}", result.reason);
                                    matched_messages.push(result);
                                }
                                MatchSource::AI => {
                                    warn!("Unexpected AI match during rule phase");
                                }
                            }
                        } else {
                            unmatched_messages.push(message);
                        }
                    }

                    // Second pass: AI-based filtering (only in hybrid mode for unmatched messages)
                    if is_hybrid && !unmatched_messages.is_empty() {
                        // Switch to AI mode
                        if let Some(hybrid_filter) = self.filter.as_any_mut().downcast_mut::<HybridFilter>() {
                            hybrid_filter.set_mode(HybridMode::AI);
                            debug!("Switched to AI mode for processing {} unmatched messages", unmatched_messages.len());
                        }

                        for message in unmatched_messages {
                            if let Some(result) = self.filter.classify_message(message) {
                                match result.source {
                                    MatchSource::AI => {
                                        ai_matches += 1;
                                        debug!("Message matched AI-based filter: {}", result.reason);
                                        matched_messages.push(result);
                                    }
                                    MatchSource::Rule => {
                                        warn!("Unexpected rule match during AI phase");
                                    }
                                }
                            }
                        }

                        // Reset back to Rules mode
                        if let Some(hybrid_filter) = self.filter.as_any_mut().downcast_mut::<HybridFilter>() {
                            hybrid_filter.set_mode(HybridMode::Rules);
                            debug!("Reset to Rules mode after AI processing");
                        }
                    }

                    // Move matched messages
                    if !matched_messages.is_empty() {
                        let mut messages_by_folder: HashMap<String, Vec<String>> = HashMap::new();
                        for result in &matched_messages {
                            messages_by_folder
                                .entry(result.target_folder.clone())
                                .or_insert_with(Vec::new)
                                .push(result.uid.clone());
                        }

                        // Move messages and track successful moves
                        for (folder, uids) in &messages_by_folder {
                            let mut folder_map = HashMap::new();
                            folder_map.insert(folder.clone(), uids.clone());
                            
                            match imap_client.move_messages(source_folder, &folder_map) {
                                Ok(_) => {
                                    // Record successfully moved messages
                                    for uid in uids {
                                        moved_uids.insert(uid.clone());
                                    }
                                    
                                    println!("\t{} {} → {}", 
                                        style("✓").green(),
                                        style(format!("{} {}", uids.len(), if uids.len() == 1 { "message" } else { "messages" })).cyan(),
                                        style(folder).green()
                                    );
                                }
                                Err(e) => {
                                    warn!("Failed to move messages to {}: {}", folder, e);
                                }
                            }
                        }
                    }
                }
            }
            
            // Wait before next check (5 seconds)
            thread::sleep(Duration::from_secs(5));
            
            // Periodically clean up old UIDs to prevent memory growth
            if moved_uids.len() > 10000 {
                info!("Cleaning up old message UIDs");
                if let Ok(current_messages) = imap_client.fetch_messages(source_folder) {
                    let current_uids: HashSet<String> = current_messages.iter()
                        .map(|m| m.uid.to_string())
                        .collect();
                    moved_uids.retain(|uid| current_uids.contains(uid));
                }
            }
        }
    }
}

// Helper function to print results
fn print_results(moved_counts: &HashMap<String, usize>) {
    for (folder, count) in moved_counts {
        println!("\t{} {} → {}", 
            style("✓").green(),
            style(format!("{} {}", count, if *count == 1 { "message" } else { "messages" })).cyan(),
            style(folder).green()
        );
    }
}
