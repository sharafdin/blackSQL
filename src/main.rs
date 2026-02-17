//! blackSQL - Advanced SQL Injection Scanner
//! Phase 1: CLI, URL validation, banner, param list. No HTTP yet.

use blacksql::cli::{print_banner, print_error, print_status, Status};
use blacksql::config::Config;
use clap::CommandFactory;
use blacksql::validator::{extract_params_from_url, parse_post_data, validate_url};
use std::collections::HashSet;
use std::process;

fn main() {
    // No args -> print help and exit 1 (same as Python)
    if std::env::args().len() <= 1 {
        let _ = Config::command().print_help();
        process::exit(1);
    }

    print_banner();

    let config = Config::from_args();

    // Require URL (same as Python: no URL -> error and exit 1)
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

    // Build param list: from URL query and/or -p and/or --data keys (same as engine init)
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

    // Dedupe (engine uses list(set(params)))
    let params: Vec<String> = params.into_iter().collect::<HashSet<_>>().into_iter().collect();

    if params.is_empty() {
        print_status(
            "No parameters to scan. Use a URL with query parameters, -p, or --data.",
            Status::Warning,
        );
    } else {
        print_status(
            &format!("Parameters to scan: {}", params.join(", ")),
            Status::Info,
        );
    }

    // Phase 1 done: banner printed, URL validated, params shown. Exit.
}
