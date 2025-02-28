// filter.rs
use crate::config::{Config, SenderRule, SubjectRule};
use crate::imap_client::Message;
use console::style;
use log::{debug, trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use reqwest::Error;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Serialize)]
struct AiRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: i32,
    top_p: f32,
    frequency_penalty: f32,
    presence_penalty: f32,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AiResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Debug)]
pub struct MatchResult {
    pub uid: String,
    pub reason: String,
    pub target_folder: String,
}

// FilterEngine trait defines the interface for all filter implementations
pub trait FilterEngine: std::any::Any {
    fn classify_message(&self, message: &Message) -> Option<MatchResult>;
    fn get_target_folders(&self) -> Vec<String>;
    fn print_info(&self);
    
    // Add method for downcasting
    fn as_any(&self) -> &dyn std::any::Any;
}

// Rule-based filtering implementation
pub struct RuleBasedFilter {
    pub config: Config,
    default_target_folder: String,
}

impl RuleBasedFilter {
    pub fn new(config: Config, default_target_folder: String) -> Self {
        Self {
            config,
            default_target_folder,
        }
    }

    fn is_newsletter(&self, headers: &str) -> bool {
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
        } else {
            trace!("No headers detected")
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
        &self,
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

    fn check_sender_patterns(
        &self,
        sender: &str,
        rules: &[SenderRule],
    ) -> Option<(String, Option<String>)> {
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
}

impl FilterEngine for RuleBasedFilter {
    fn classify_message(&self, message: &Message) -> Option<MatchResult> {
        let mut target_folder = self.default_target_folder.clone();

        // Check headers for newsletter indicators
        if self.is_newsletter(&message.headers) {
            let reason = "Newsletter headers".to_string();
            return Some(MatchResult {
                uid: message.uid.to_string(),
                reason,
                target_folder,
            });
        }

        // Check subject against regex patterns
        if let Some((pattern_match, folder)) =
            self.check_subject_patterns(&message.subject, &self.config.subject_rules)
        {
            let reason = format!("Subject pattern: {}", pattern_match);

            // Use rule-specific folder if provided
            if let Some(rule_folder) = folder {
                target_folder = rule_folder;
            }

            return Some(MatchResult {
                uid: message.uid.to_string(),
                reason,
                target_folder,
            });
        }

        // Check sender against regex patterns if sender rules exist
        if !self.config.sender_rules.is_empty() {
            if let Some((pattern_match, folder)) =
                self.check_sender_patterns(&message.sender, &self.config.sender_rules)
            {
                let reason = format!("Sender pattern: {}", pattern_match);

                // Use rule-specific folder if provided
                if let Some(rule_folder) = folder {
                    target_folder = rule_folder;
                }

                return Some(MatchResult {
                    uid: message.uid.to_string(),
                    reason,
                    target_folder,
                });
            }
        }

        // No match found
        None
    }

    fn get_target_folders(&self) -> Vec<String> {
        self.config.get_target_folders(&self.default_target_folder)
    }

    fn print_info(&self) {
        println!("{}", style("MODE:").yellow().bold());
        println!(
            "\t• {}: {} subject rules, {} sender rules",
            style("Rule-based filtering").magenta().bold(),
            style(self.config.subject_rules.len().to_string()).cyan(),
            style(self.config.sender_rules.len().to_string()).cyan()
        );

        self.config.print_info();
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// AI-based filtering implementation
pub struct AiFilter {
    available_folders: Vec<String>,
    default_target_folder: String,
    lmstudio_url: String,
    model: String,
    system_prompt: String,
}

impl AiFilter {
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000; // 1 second delay between retries
    const DEFAULT_MODEL: &'static str = "mistral-nemo-instruct-2407";
    const DEFAULT_LMSTUDIO_URL: &'static str = "http://localhost:1234";

    fn extract_json_content(content: &str) -> &str {
        // If the content contains ```json or ``` markers, extract just the JSON part
        if let Some(start) = content.find("```json") {
            // Look for the closing ``` after the start position
            if let Some(end) = content[start + 7..].find("```") {
                // Skip the ```json marker and any whitespace
                let json_start = start + 7;
                let content = content[json_start..json_start + end].trim();
                return content;
            }
        } else if let Some(start) = content.find("```") {
            // Look for the closing ``` after the start position
            if let Some(end) = content[start + 3..].find("```") {
                // Skip the ``` marker and any whitespace
                let json_start = start + 3;
                let content = content[json_start..json_start + end].trim();
                return content;
            }
        }
        // If no markers found or invalid format, return the original content
        content.trim()
    }

    pub fn new(
        available_folders: Vec<String>, 
        default_target_folder: String, 
        lmstudio_url: Option<String>,
        model: Option<&str>,
    ) -> Self {
        let model = model.map(String::from).unwrap_or_else(|| Self::DEFAULT_MODEL.to_string());
        let lmstudio_url = lmstudio_url.unwrap_or_else(|| Self::DEFAULT_LMSTUDIO_URL.to_string());
        let lmstudio_url = if !lmstudio_url.ends_with("/v1/chat/completions") {
            format!("{}/v1/chat/completions", lmstudio_url.trim_end_matches('/'))
        } else {
            lmstudio_url
        };
        let folders_list = available_folders.join(", ");
        let system_prompt = format!(
            "You are an email classification assistant. Your ONLY task is to assign emails to EXISTING folders. \
            ===AVAILABLE FOLDERS=== \
            The ONLY valid folders you can use are listed below. You MUST use EXACT spelling, capitalization, and the EXACT path as shown. \
            {} \
            \
            ===DEFAULT FOLDER===
            If you're unsure where to file an email, ALWAYS use this default folder: {}. \
            \
            INSTRUCTIONS: \
            1. Look at the email's subject, sender, headers and content \
            2. Select ONE folder from the AVAILABLE FOLDERS list above - use EXACT spelling, capitalization, and path as shown in the list \
            3. If uncertain, use the DEFAULT FOLDER \
            4. Provide a brief reason \
            5. Remember that the objective is to clean up your inbox, so if the email is not important, move it to another folder. \
            6. Many emails are notifications, but attempt to classify them in one of the other folders first. \
            \
            Your response must be ONLY this JSON format:: \
            {{\
                \"target_folder\": \"EXACT_FOLDER_NAME_FROM_LIST\",\
                \"reason\": \"Brief explanation\"\
            }}\
            \
            EXAMPLE OF CORRECT RESPONSE:
            {{\
                \"target_folder\": \"INBOX/Notifications\",\
                \"reason\": \"Subject contains 'Notification' and sender is 'notifications@github.com', that's a notification email\"\
            }}\
            \
            \
            Base your decision on the email's subject, sender, headers, and body content. \
            Consider factors like: \
            - Is it a newsletter or promotional content? \
            - Is it from a known sender or organization? \
            - What is the main topic or purpose of the email? \
            - Are there any specific keywords or patterns that indicate its category? \
            - Does it look like it is an actual person, not an automated message? In that case, it should remain in INBOX \
            - Note: Specialized folders like 'TrueNAS - Alerts' are ONLY for alerts coming from TrueNAS, they MUST NOT be used for other emails. Folders under 'Lists' are for their respective mailing lists.\
            \
            CRITICAL: You MUST select a folder from the EXACT list provided. DO NOT modify folder names or paths in any way. \
            DO NOT add, remove, or change any part of the folder name. Use the COMPLETE folder path exactly as shown. \
            For example, if the list contains 'INBOX/Trades' but not 'Trades', you MUST use 'INBOX/Trades'.\
            \
            VERIFICATION: Before responding, verify that your 'target_folder' is an EXACT copy-paste of one of the available folders listed above.\
            ", 
            folders_list,
            default_target_folder
        );

        Self {
            available_folders,
            default_target_folder,
            lmstudio_url,
            model,
            system_prompt,
        }
    }

    async fn call_external_ai(&self, message: &Message) -> Result<Option<(String, String)>, Error> {
        let client = reqwest::Client::new();
        
        // Create the message content
        let content = format!(
            "Please analyze this email:\nFrom: {}\nSubject: {}\n\nHeaders:\n{}\n\nBody:\n{}",
            message.sender,
            message.subject,
            message.headers,
            message.body.as_ref().cloned().unwrap_or_else(|| "".to_string())
        );

        let request = AiRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: self.system_prompt.clone(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content,
                },
            ],
            temperature: 0.3,
            max_tokens: 500,
            top_p: 1.0,
            frequency_penalty: 0.0,
            presence_penalty: 0.0,
        };

        let mut attempts = 0;
        let mut invalid_folder_attempts = 0;
        const MAX_INVALID_FOLDER_RETRIES: u32 = 2;

        while attempts < Self::MAX_RETRIES {
            attempts += 1;
            
            debug!("Calling LM Studio API for classification (attempt {})", attempts);
            trace!("Message subject: {}", message.subject);
            trace!("Message sender: {}", message.sender);

            let response = client
                .post(&self.lmstudio_url)
                .header("Content-Type", "application/json")
                .json(&request)
                .send()
                .await?
                .json::<AiResponse>()
                .await?;

            // Parse the JSON response from the model's output
            if let Some(choice) = response.choices.first() {
                let json_content = Self::extract_json_content(&choice.message.content);
                match serde_json::from_str::<ModelResponse>(json_content) {
                    Ok(parsed) => {
                        // Verify the target folder is valid
                        debug!("Validating suggested folder: '{}'", parsed.target_folder);
                        let contains_folder = self.available_folders.contains(&parsed.target_folder);
                        debug!("Folder validation result for '{}': {}", parsed.target_folder, contains_folder);
                        
                        if contains_folder {
                            return Ok(Some((parsed.target_folder, parsed.reason)));
                        } else {
                            invalid_folder_attempts += 1;
                            warn!(
                                "AI suggested invalid folder '{}' for message '{}' (attempt {}/{}). Reason given: '{}'.",
                                parsed.target_folder,
                                message.subject,
                                invalid_folder_attempts,
                                MAX_INVALID_FOLDER_RETRIES + 1,
                                parsed.reason
                            );
                            
                            // Let's print a few folders that might be similar to help diagnose the issue
                            for folder in &self.available_folders {
                                if folder.contains(&parsed.target_folder) || 
                                   parsed.target_folder.contains(folder) ||
                                   folder.split('/').last() == parsed.target_folder.split('/').last() {
                                    debug!("Possible similar folder: '{}'", folder);
                                }
                            }

                            if invalid_folder_attempts <= MAX_INVALID_FOLDER_RETRIES {
                                debug!("Retrying with the same message...");
                                continue;
                            } else {
                                warn!("Exceeded maximum retries for invalid folder suggestions. Skipping message.");
                                return Ok(None);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse AI response for message '{}' (attempt {}/{}). Error: {}. Raw response: {}",
                            message.subject,
                            attempts,
                            Self::MAX_RETRIES,
                            e,
                            choice.message.content
                        );
                        
                        if attempts < Self::MAX_RETRIES {
                            debug!("Retrying in {} ms...", Self::RETRY_DELAY_MS);
                            sleep(Duration::from_millis(Self::RETRY_DELAY_MS)).await;
                            continue;
                        }
                    }
                }
            }
        }

        warn!(
            "Failed to get valid JSON response after {} attempts for message '{}'",
            Self::MAX_RETRIES,
            message.subject
        );
        Ok(None)
    }
}

impl FilterEngine for AiFilter {
    fn classify_message(&self, message: &Message) -> Option<MatchResult> {
        // Call the AI service to classify the message
        let response = tokio::runtime::Runtime::new().unwrap().block_on(self.call_external_ai(message));
        if let Ok(Some((target_folder, reason))) = response {
            debug!(
                "AI classified message: {} '{}' -> {} (Reason: {})",
                message.uid, message.subject, target_folder, reason
            );

            return Some(MatchResult {
                uid: message.uid.to_string(),
                reason,
                target_folder,
            });
        }

        None
    }

    fn get_target_folders(&self) -> Vec<String> {
        // In a real implementation, you might want to analyze past AI decisions
        // to provide a more complete list of potential target folders
        vec![self.default_target_folder.clone()]
    }

    fn print_info(&self) {
        println!("{}", style("MODE:").yellow().bold());
        println!("\t• {}", style("AI-based email classification").magenta().bold());
        println!("\t  {} {}", style("Model:").cyan(), style(&self.model).green());
        println!("\t  {} {}", style("Default target:").cyan(), style(&self.default_target_folder).green());
        println!(
            "\t  {} {}",
            style("Available folders:").cyan(),
            style(self.available_folders.len().to_string()).green()
        );
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// Hybrid filtering implementation that combines rules and AI
pub struct HybridFilter {
    pub rule_filter: RuleBasedFilter,
    pub ai_filter: AiFilter,
}

impl HybridFilter {
    pub fn new(
        config: Config,
        available_folders: Vec<String>,
        default_target_folder: String,
        lmstudio_url: Option<String>,
        model: Option<&str>,
    ) -> Self {
        Self {
            rule_filter: RuleBasedFilter::new(config, default_target_folder.clone()),
            ai_filter: AiFilter::new(available_folders, default_target_folder, lmstudio_url, model),
        }
    }
}

impl FilterEngine for HybridFilter {
    fn classify_message(&self, message: &Message) -> Option<MatchResult> {
        // First try rule-based filtering
        if let Some(result) = self.rule_filter.classify_message(message) {
            debug!("Message matched rule-based filter: {}", result.reason);
            return Some(result);
        }

        // If no rule matches, try AI-based filtering
        debug!("No rule matches found, trying AI classification");
        self.ai_filter.classify_message(message)
    }

    fn get_target_folders(&self) -> Vec<String> {
        // Combine target folders from both filters, removing duplicates
        let mut folders = self.rule_filter.get_target_folders();
        let ai_folders = self.ai_filter.get_target_folders();
        
        for folder in ai_folders {
            if !folders.contains(&folder) {
                folders.push(folder);
            }
        }
        
        folders
    }

    fn print_info(&self) {
        println!("{}", style("MODE:").yellow().bold());
        println!("\t• {}", style("Hybrid filtering (rules + AI)").magenta().bold());
        println!("\t  {} {}", style("Processing:").cyan(), style("Two-pass (rules first, then AI)").green());
        
        // Print rule-based filter info
        let rule_count = self.rule_filter.config.subject_rules.len() + 
                        self.rule_filter.config.sender_rules.len();
        println!("\t  {} {}", style("Rules:").cyan(), style(rule_count).green());
        
        // Print AI filter info
        println!("\t  {} {}", style("Model:").cyan(), style(&self.ai_filter.model).green());
        println!("\t  {} {}", style("Default target:").cyan(), style(&self.ai_filter.default_target_folder).green());
        
        // Print detailed rule info
        self.rule_filter.config.print_info();
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Deserialize)]
struct ModelResponse {
    target_folder: String,
    reason: String,
}
