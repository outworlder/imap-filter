// filter.rs
use crate::config::{Config, SenderRule, SubjectRule};
use crate::imap_client::Message;
use log::{debug, trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
pub trait FilterEngine {
    fn classify_message(&self, message: &Message) -> Option<MatchResult>;
    fn get_target_folders(&self) -> Vec<String>;
    fn print_info(&self);
}

// Rule-based filtering implementation
pub struct RuleBasedFilter {
    config: Config,
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
        let mut reason = String::new();
        let mut target_folder = self.default_target_folder.clone();

        // Check headers for newsletter indicators
        if self.is_newsletter(&message.headers) {
            reason = "Newsletter headers".to_string();
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
            reason = format!("Subject pattern: {}", pattern_match);

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
                reason = format!("Sender pattern: {}", pattern_match);

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
        println!(
            "Using rule-based filtering with {} subject rules and {} sender rules",
            self.config.subject_rules.len(),
            self.config.sender_rules.len()
        );

        self.config.print_info();
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

    pub fn new(available_folders: Vec<String>, default_target_folder: String, lmstudio_url: String) -> Self {
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
            \
            Your response must be ONLY this JSON format:: \
            {{\
                \"target_folder\": \"EXACT_FOLDER_NAME_FROM_LIST\",\
                \"reason\": \"Brief explanation\"\
            }}\
            \
            EXAMPLE OF CORRECT RESPONSE:
            {{\
                \"target_folder\": \"Notifications\",\
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
            lmstudio_url: if !lmstudio_url.ends_with("/v1/chat/completions") {
                format!("{}/v1/chat/completions", lmstudio_url.trim_end_matches('/'))
            } else {
                lmstudio_url
            },
            model: "mistral-nemo-instruct-2407".to_string(), // Using OpenAI model name format
            //model: "qwen2.5-coder-1.5b-instruct-mlx".to_string(), // Using OpenAI model name format

            
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
                match serde_json::from_str::<ModelResponse>(&choice.message.content) {
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
        println!("Using AI-based email classification");
        println!("Default target folder: {}", self.default_target_folder);
        println!(
            "Available folders for AI decisions: {}",
            self.available_folders.len()
        );
    }
}

#[derive(Debug, Deserialize)]
struct ModelResponse {
    target_folder: String,
    reason: String,
}
