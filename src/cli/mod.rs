//! CLI output - banner and colored status. Port of legacy/lib/utils/cli.py

use colored::Colorize;

use crate::logger;

/// Print the blackSQL banner (same as Python print_banner).
pub fn print_banner() {
    let line1 = "█▄▄ █░░ ▄▀█ █▀▀ █▄▀   █▀ █▀█ █░░";
    let line2 = "█▄█ █▄▄ █▀█ █▄▄ █░█   ▄█ █▄█ █▄▄";
    println!("\n{}", format!("{}\n{}", line1, line2).red());
    println!("{} Advanced SQL Injection Scanner", "[*]".cyan());
    println!("{} Author: Mr Sharafdin", "[*]".cyan());
    println!("{} Version: 1.0.0\n", "[*]".cyan());
    if logger::is_active() {
        logger::log("INFO", "blackSQL scan started");
    }
}

/// Status kind for print_status.
#[derive(Clone, Copy)]
pub enum Status {
    Success,
    Info,
    Warning,
    Error,
    Vuln,
}

/// Print a status line with prefix and color. Same as Python print_status(message, status).
/// When file logging is active, only WARNING/ERROR/VULN are shown on console; all go to file.
pub fn print_status(message: &str, status: Status) {
    let (prefix, level) = match status {
        Status::Success => ("[+]", "INFO"),
        Status::Info => ("[*]", "INFO"),
        Status::Warning => ("[!]", "WARNING"),
        Status::Error => ("[-]", "ERROR"),
        Status::Vuln => ("[VULNERABLE]", "ERROR"),
    };
    let log_msg = format!("{} {}", prefix, message);
    logger::log(level, &log_msg);
    let show_on_console = !logger::is_active()
        || matches!(status, Status::Warning | Status::Error | Status::Vuln);
    if show_on_console {
        let colored_msg = match status {
            Status::Success => message.green(),
            Status::Info => message.cyan(),
            Status::Warning => message.yellow(),
            Status::Error | Status::Vuln => message.red(),
        };
        println!("{} {}", prefix.cyan(), colored_msg);
    }
}

/// Print red error message (for fatal errors). Also written to log file when active.
pub fn print_error(msg: &str) {
    logger::log("ERROR", msg);
    eprintln!("{}", msg.red());
}

/// Print yellow message (e.g. interrupted).
pub fn print_warning(msg: &str) {
    eprintln!("{}", msg.yellow());
}

/// Progress bar: same as Python progress_bar(iteration, total, prefix, suffix, length=50).
pub fn progress_bar(iteration: usize, total: usize, prefix: &str, suffix: &str) {
    let length = 50;
    let fill = '█';
    let percent = if total > 0 {
        100.0 * (iteration as f64 / total as f64)
    } else {
        100.0
    };
    let filled = if total > 0 {
        (length * iteration / total).min(length)
    } else {
        length
    };
    let bar: String = (0..length)
        .map(|i| if i < filled { fill } else { '-' })
        .collect();
    print!("\r{} |{}| {:.1}% {}", prefix, bar, percent, suffix);
    let _ = std::io::Write::flush(&mut std::io::stdout());
    if iteration == total {
        println!();
    }
}
