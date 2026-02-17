//! CLI output - banner and colored status. Port of legacy/lib/utils/cli.py

use colored::Colorize;

/// Print the blackSQL banner (same as Python print_banner).
pub fn print_banner() {
    let line1 = "█▄▄ █░░ ▄▀█ █▀▀ █▄▀   █▀ █▀█ █░░";
    let line2 = "█▄█ █▄▄ █▀█ █▄▄ █░█   ▄█ █▄█ █▄▄";
    println!(
        "\n{}",
        format!("{}\n{}", line1, line2).red()
    );
    println!("{} Advanced SQL Injection Scanner", "[*]".cyan());
    println!("{} Author: Mr Sharafdin", "[*]".cyan());
    println!("{} Version: 1.0.0\n", "[*]".cyan());
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
pub fn print_status(message: &str, status: Status) {
    let (prefix, colored_msg) = match status {
        Status::Success => ("[+]", message.green()),
        Status::Info => ("[*]", message.cyan()),
        Status::Warning => ("[!]", message.yellow()),
        Status::Error => ("[-]", message.red()),
        Status::Vuln => ("[VULNERABLE]", message.red()),
    };
    println!("{} {}", prefix.cyan(), colored_msg);
}

/// Print red error message (for fatal errors).
pub fn print_error(msg: &str) {
    eprintln!("{}", msg.red());
}

/// Print yellow message (e.g. interrupted).
pub fn print_warning(msg: &str) {
    eprintln!("{}", msg.yellow());
}
