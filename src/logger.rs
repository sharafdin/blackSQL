//! File logger - port of legacy/lib/utils/logger.py setup_logger.
//! Log file: path from -o or logs/blacksql_{timestamp}.log. Console at WARNING when file is active.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use once_cell::sync::OnceCell;

static LOG: OnceCell<Arc<Mutex<fs::File>>> = OnceCell::new();

/// Initialize file logger. Creates logs/ if using default path.
/// If output is None, uses logs/blacksql_{timestamp}.log.
pub fn init(output: Option<&Path>) -> io::Result<()> {
    let path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = Path::new("logs");
            fs::create_dir_all(dir)?;
            dir.join(format!("blacksql_{}.log", Utc::now().format("%Y%m%d_%H%M%S")))
        }
    };
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let f = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    let _ = LOG.set(Arc::new(Mutex::new(f)));
    Ok(())
}

/// True if file logging is active (console should show only WARNING+).
pub fn is_active() -> bool {
    LOG.get().is_some()
}

/// Write a line to the log file if active. Format: "timestamp - LEVEL - message"
pub fn log(level: &str, message: &str) {
    if let Some(arc) = LOG.get() {
        let mut f = arc.lock().unwrap();
        let line = format!(
            "{} - {} - {}\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            level,
            message
        );
        let _ = io::Write::write_all(&mut *f, line.as_bytes());
    }
}
