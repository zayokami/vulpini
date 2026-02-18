use std::fs::{File, OpenOptions};
use std::io::Write;
use parking_lot::Mutex;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
}

struct LogFile {
    file: Mutex<File>,
    level: LogLevel,
}

impl LogFile {
    fn new(path: &str, level: LogLevel) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        
        Ok(LogFile {
            file: Mutex::new(file),
            level,
        })
    }

    fn write(&self, level: LogLevel, message: &str) {
        if level < self.level {
            return;
        }
        
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let level_str = match level {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        
        let log_line = format!("[{}] [{}] {}\n", timestamp, level_str, message);
        
        let mut file = self.file.lock();
        let _ = file.write_all(log_line.as_bytes());
    }
}

pub struct Logger {
    file: Option<LogFile>,
    level: LogLevel,
}

impl Logger {
    pub fn new(log_file: &str, level: log::LevelFilter) -> Result<Self, std::io::Error> {
        let rust_log_level = match level {
            log::LevelFilter::Trace => LogLevel::Trace,
            log::LevelFilter::Debug => LogLevel::Debug,
            log::LevelFilter::Info => LogLevel::Info,
            log::LevelFilter::Warn => LogLevel::Warn,
            log::LevelFilter::Error => LogLevel::Error,
            _ => LogLevel::Info,
        };
        
        let file = LogFile::new(log_file, rust_log_level)?;
        
        let logger = Logger {
            file: Some(file),
            level: rust_log_level,
        };
        
        Ok(logger)
    }

    pub fn trace(&self, message: &str) {
        self.log(LogLevel::Trace, message);
    }

    pub fn debug(&self, message: &str) {
        self.log(LogLevel::Debug, message);
    }

    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    pub fn warn(&self, message: &str) {
        self.log(LogLevel::Warn, message);
    }

    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }

    fn log(&self, level: LogLevel, message: &str) {
        if level < self.level {
            return;
        }
        
        if let Some(ref file) = self.file {
            file.write(level, message);
        }
        
        println!("[vulpini] [{}] {}", level_str(level), message);
    }
}

fn level_str(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "TRACE",
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
    }
}
