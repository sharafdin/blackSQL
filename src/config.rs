//! CLI configuration - same interface as legacy/blacksql.py

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "blacksql",
    about = "blackSQL - Advanced SQL Injection Scanner",
    author = "Mr Sharafdin",
    version
)]
pub struct Config {
    /// Target URL (e.g., http://example.com/page.php?id=1)
    #[arg(short = 'u', long = "url")]
    pub url: Option<String>,

    /// Specify parameters to scan (e.g., 'id,page')
    #[arg(short = 'p', long = "params")]
    pub params: Option<String>,

    /// POST data (e.g., 'id=1&page=2')
    #[arg(long = "data")]
    pub data: Option<String>,

    /// HTTP cookies (e.g., 'PHPSESSID=value; admin=0')
    #[arg(short = 'c', long = "cookies")]
    pub cookies: Option<String>,

    /// Number of threads (default: 5)
    #[arg(short = 't', long = "threads", default_value = "5")]
    pub threads: u32,

    /// Connection timeout in seconds (default: 10.0)
    #[arg(long = "timeout", default_value = "10.0")]
    pub timeout: f64,

    /// Use a proxy (e.g., 'http://127.0.0.1:8080')
    #[arg(long = "proxy")]
    pub proxy: Option<String>,

    /// Scan level 1-3 (higher = more tests)
    #[arg(long = "level", value_parser = clap::value_parser!(u8).range(1..=3), default_value = "1")]
    pub level: u8,

    /// Attempt to dump database tables when vulnerable
    #[arg(long = "dump", action = clap::ArgAction::SetTrue)]
    pub dump: bool,

    /// Never ask for user input, use the default behavior
    #[arg(long = "batch", action = clap::ArgAction::SetTrue)]
    pub batch: bool,

    /// Save scan results / log file path
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}

impl Config {
    /// Parse from env args. If no args given, returns None (caller should print help and exit).
    pub fn from_args() -> Self {
        Self::parse()
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn params_list(&self) -> Option<Vec<String>> {
        self.params.as_ref().map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
    }
}
