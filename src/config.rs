// config.rs
use console::style;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub subject_rules: Vec<SubjectRule>,
    #[serde(default)]
    pub sender_rules: Vec<SenderRule>,
    #[serde(default)]
    pub ai_prompt: Option<String>,
    // Command line parameters that can be specified in config
    pub server: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub source_folder: Option<String>,
    pub target_folder: Option<String>,
    pub model: Option<String>,
    pub lmstudio_url: Option<String>,
    pub use_ai: Option<bool>,
    pub use_hybrid: Option<bool>,
    pub skip_confirmation: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubjectRule {
    pub pattern: String,
    pub description: Option<String>,
    pub folder: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SenderRule {
    pub pattern: String,
    pub description: Option<String>,
    pub folder: Option<String>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Config {
            subject_rules: vec![],
            sender_rules: vec![],
            ai_prompt: None,
            server: None,
            port: None,
            username: None,
            source_folder: None,
            target_folder: None,
            model: None,
            lmstudio_url: None,
            use_ai: None,
            use_hybrid: None,
            skip_confirmation: None,
        }
    }

    // Get all unique target folders specified in the rules
    pub fn get_target_folders(&self, default_folder: &str) -> Vec<String> {
        let mut folders = vec![default_folder.to_string()];

        // Add folders from subject rules
        for rule in &self.subject_rules {
            if let Some(folder) = &rule.folder {
                if !folders.contains(folder) {
                    folders.push(folder.clone());
                }
            }
        }

        // Add folders from sender rules
        for rule in &self.sender_rules {
            if let Some(folder) = &rule.folder {
                if !folders.contains(folder) {
                    folders.push(folder.clone());
                }
            }
        }

        folders
    }

    pub fn print_info(&self) {
        if !self.subject_rules.is_empty() {
            println!("\n\t{}", style("SUBJECT PATTERNS:").cyan().bold());
            for (i, rule) in self.subject_rules.iter().enumerate() {
                let folder_info = if let Some(folder) = &rule.folder {
                    format!(" → {}", style(folder).green())
                } else {
                    "".to_string()
                };

                if let Some(desc) = &rule.description {
                    println!("\t  {}. {} - {}{}", 
                        style(i + 1).blue(), 
                        style(&rule.pattern).magenta(), 
                        style(desc).dim(), 
                        folder_info
                    );
                } else {
                    println!("\t  {}. {}{}", 
                        style(i + 1).blue(), 
                        style(&rule.pattern).magenta(), 
                        folder_info
                    );
                }
            }
        }

        if !self.sender_rules.is_empty() {
            println!("\n\t{}", style("SENDER PATTERNS:").cyan().bold());
            for (i, rule) in self.sender_rules.iter().enumerate() {
                let folder_info = if let Some(folder) = &rule.folder {
                    format!(" → {}", style(folder).green())
                } else {
                    "".to_string()
                };

                if let Some(desc) = &rule.description {
                    println!("\t  {}. {} - {}{}", 
                        style(i + 1).blue(), 
                        style(&rule.pattern).magenta(), 
                        style(desc).dim(), 
                        folder_info
                    );
                } else {
                    println!("\t  {}. {}{}", 
                        style(i + 1).blue(), 
                        style(&rule.pattern).magenta(), 
                        folder_info
                    );
                }
            }
        }
    }
}
