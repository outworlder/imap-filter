// config.rs
use serde::Deserialize;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub subject_rules: Vec<SubjectRule>,
    #[serde(default)]
    pub sender_rules: Vec<SenderRule>,
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
        println!(
            "Using {} subject regex rules and {} sender regex rules",
            self.subject_rules.len(),
            self.sender_rules.len()
        );

        if !self.subject_rules.is_empty() {
            println!("\nConfigured subject patterns:");
            for (i, rule) in self.subject_rules.iter().enumerate() {
                let folder_info = if let Some(folder) = &rule.folder {
                    format!(" -> {}", folder)
                } else {
                    "".to_string()
                };

                if let Some(desc) = &rule.description {
                    println!("  {}. {} - {}{}", i + 1, rule.pattern, desc, folder_info);
                } else {
                    println!("  {}. {}{}", i + 1, rule.pattern, folder_info);
                }
            }
        }

        if !self.sender_rules.is_empty() {
            println!("\nConfigured sender patterns:");
            for (i, rule) in self.sender_rules.iter().enumerate() {
                let folder_info = if let Some(folder) = &rule.folder {
                    format!(" -> {}", folder)
                } else {
                    "".to_string()
                };

                if let Some(desc) = &rule.description {
                    println!("  {}. {} - {}{}", i + 1, rule.pattern, desc, folder_info);
                } else {
                    println!("  {}. {}{}", i + 1, rule.pattern, folder_info);
                }
            }
        }
    }
}
