//! blackSQL - Advanced SQL Injection Scanner

use blacksql::cli::{print_banner, print_error, print_status, Status};
use blacksql::config::Config;
use blacksql::engine::{run_scan, ScannerConfig};
use blacksql::validator::{extract_params_from_url, parse_cookies, parse_post_data, validate_url};
use clap::CommandFactory;
use std::collections::HashSet;
use std::process;

fn main() {
    ctrlc::set_handler(move || {
        blacksql::cli::print_status("Scan interrupted by user", blacksql::cli::Status::Warning);
        process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    if std::env::args().len() <= 1 {
        let _ = Config::command().print_help();
        process::exit(1);
    }

    let config = Config::from_args();

    if let Err(e) = blacksql::logger::init(config.output.as_deref()) {
        eprintln!("Warning: could not create log file: {}", e);
    }

    print_banner();

    let url = match config.url() {
        Some(u) => u,
        None => {
            print_error("Error: Target URL is required");
            process::exit(1);
        }
    };

    if !validate_url(url) {
        print_error(&format!("Error: Invalid URL format: {}", url));
        process::exit(1);
    }

    let mut params: Vec<String> = Vec::new();
    if let Some(ref p) = config.params_list() {
        params.extend(p.clone());
    }
    if params.is_empty() {
        let from_url = extract_params_from_url(url);
        params.extend(from_url.into_keys());
    }
    if let Some(ref data_str) = config.data {
        let post = parse_post_data(data_str);
        for k in post.keys() {
            params.push(k.clone());
        }
    }
    let params: Vec<String> = params.into_iter().collect::<HashSet<_>>().into_iter().collect();

    if params.is_empty() {
        print_status(
            "No parameters to scan. Use a URL with query parameters, -p, or --data.",
            Status::Warning,
        );
        return;
    }

    let data = config
        .data
        .as_deref()
        .map(parse_post_data)
        .unwrap_or_default();
    let cookies = config
        .cookies
        .as_deref()
        .map(parse_cookies)
        .unwrap_or_default();

    let scan_config = ScannerConfig {
        url: url.to_string(),
        params,
        data,
        cookies,
        threads: config.threads,
        timeout: config.timeout,
        proxy: config.proxy.clone(),
        level: config.level,
        dump: config.dump,
        batch: config.batch,
    };

    let _vulnerabilities = run_scan(scan_config);
}
