use std::fs::{self, File, OpenOptions};
use std::io::Write;
use chrono::Local;
use std::path::PathBuf;

pub struct AiLogger {
    file: File,
    log_path: PathBuf,
}

impl AiLogger {
    pub fn new() -> std::io::Result<Self> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let log_dir = "logs";
        let log_path = PathBuf::from(format!("{}/ai_reasoning_{}.log", log_dir, timestamp));
        
        fs::create_dir_all(log_dir)?;
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&log_path)?;
            
        Ok(AiLogger { file, log_path })
    }
    
    pub fn log_reasoning(&mut self, message_subject: &str, reasoning: &str) -> std::io::Result<()> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(
            self.file,
            "\n=== {} ===\nSubject: {}\nReasoning:\n{}\n",
            timestamp,
            message_subject,
            reasoning
        )?;
        self.file.flush()?;
        Ok(())
    }
    
    pub fn get_log_path(&self) -> &PathBuf {
        &self.log_path
    }
} 