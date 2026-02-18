//! Scanner engine - port of legacy/lib/core/engine.py

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::cli::{print_status, progress_bar, Status};
use crate::http_client::RequestHandler;
use crate::payloads::{prepare_payloads, PreparedPayloads};
use crate::techniques::{scan_boolean_based, scan_error_based, scan_time_based, scan_union_based, extract_all, ScanContext};
use crate::waf_detector;

/// Result for one parameter (same shape as Python engine result).
#[derive(Clone, Debug)]
pub struct ParamResult {
    pub parameter: String,
    pub is_vulnerable: bool,
    pub techniques: Vec<String>,
    pub database_type: Option<String>,
    /// Set when --dump and vulnerable (Phase 6).
    pub extraction: Option<crate::techniques::ExtractionResults>,
}

/// Scanner config (same as Python Scanner.__init__ args).
pub struct ScannerConfig {
    pub url: String,
    pub params: Vec<String>,
    pub data: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub threads: u32,
    pub timeout: f64,
    pub proxy: Option<String>,
    pub level: u8,
    pub dump: bool,
    pub batch: bool,
}

/// Run all techniques on one parameter. Order: error → boolean → time; if vulnerable or level 3 → union.
fn scan_one_parameter(
    url: &str,
    handler: &RequestHandler,
    parameter: &str,
    data: &HashMap<String, String>,
    level: u8,
    dump: bool,
    prepared: &PreparedPayloads,
) -> ParamResult {
    let is_post = data.contains_key(parameter);
    let data_opt = if is_post { Some(data) } else { None };
    let ctx = ScanContext {
        url,
        handler,
        is_post,
        data: data_opt,
    };

    let mut techniques = Vec::new();
    let mut database_type: Option<String> = None;

    let r_error = scan_error_based(&ctx, parameter, &prepared.error);
    if r_error.vulnerable {
        techniques.push("Error-based".to_string());
        if r_error.db_type.as_deref() != Some("Unknown") {
            database_type = r_error.db_type.clone();
        }
    }

    let r_bool = scan_boolean_based(&ctx, parameter, &prepared.boolean);
    if r_bool.vulnerable {
        techniques.push("Boolean-based".to_string());
        if r_bool.db_type.as_deref() != Some("Unknown") {
            database_type = database_type.or(r_bool.db_type.clone());
        }
    }

    let r_time = scan_time_based(&ctx, parameter, &prepared.time);
    if r_time.vulnerable {
        techniques.push("Time-based".to_string());
        if r_time.db_type.as_deref() != Some("Unknown") {
            database_type = database_type.or(r_time.db_type.clone());
        }
    }

    let run_union = !techniques.is_empty() || level == 3;
    if run_union {
        let r_union = scan_union_based(&ctx, parameter);
        if r_union.vulnerable {
            techniques.push("Union-based".to_string());
            if r_union.db_type.as_deref() != Some("Unknown") {
                database_type = database_type.or(r_union.db_type.clone());
            }
        }
    }

    let is_vulnerable = !techniques.is_empty();
    let extraction = if is_vulnerable && dump {
        print_status(
            &format!("Attempting to extract database information from parameter: {}", parameter),
            Status::Info,
        );
        let ctx = ScanContext { url, handler, is_post, data: data_opt };
        Some(extract_all(&ctx, parameter, database_type.as_deref()))
    } else {
        None
    };

    ParamResult {
        parameter: parameter.to_string(),
        is_vulnerable,
        techniques,
        database_type,
        extraction,
    }
}

/// Start the scan: WAF check, parallel workers, progress bar, summary.
pub fn run_scan(config: ScannerConfig) -> Vec<ParamResult> {
    let level = config.level.clamp(1, 3);
    let mut use_waf_bypass = true;

    let handler = match RequestHandler::with_cookies(
        config.timeout,
        config.proxy.as_deref(),
        &config.cookies,
    ) {
        Ok(h) => Arc::new(h),
        Err(e) => {
            print_status(&format!("Failed to create HTTP client: {}", e), Status::Error);
            return Vec::new();
        }
    };

    if config.params.is_empty() {
        print_status(
            "No parameters to scan. Use --params or a URL with query parameters or --data.",
            Status::Warning,
        );
        return Vec::new();
    }

    print_status("Checking if target is protected by a WAF...", Status::Info);
    let (is_waf, _) = waf_detector::check_target(handler.as_ref(), &config.url);
    if is_waf {
        use_waf_bypass = true;
    }

    let mut prepared = prepare_payloads(level, use_waf_bypass);
    if is_waf {
        prepared = prepare_payloads(level, true);
    }

    print_status(&format!("Parameters to scan: {}", config.params.join(", ")), Status::Info);
    print_status(&format!("Starting scan with {} threads", config.threads), Status::Info);

    let start = Instant::now();
    let n = config.params.len();
    let num_workers = config.threads as usize;
    let num_workers = num_workers.min(n).max(1);

    let queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(config.params.clone()));
    let (tx, rx) = mpsc::channel::<ParamResult>();

    let url = config.url.clone();
    let data = config.data.clone();

    let dump = config.dump;
    for _ in 0..num_workers {
        let url_c = url.clone();
        let handler_c = Arc::clone(&handler);
        let data_c = data.clone();
        let prepared_c = prepared.clone();
        let queue_c = Arc::clone(&queue);
        let tx_c = tx.clone();
        thread::spawn(move || {
            loop {
                let param = {
                    let mut q = queue_c.lock().unwrap();
                    q.pop()
                };
                let param = match param {
                    Some(p) => p,
                    None => break,
                };
                let result = scan_one_parameter(
                    &url_c,
                    handler_c.as_ref(),
                    &param,
                    &data_c,
                    level,
                    dump,
                    &prepared_c,
                );
                let _ = tx_c.send(result);
            }
        });
    }
    drop(tx);

    let mut vulnerabilities = Vec::new();
    for (i, received) in rx.iter().enumerate() {
        let done = i + 1;
        progress_bar(
            done,
            n,
            "Progress:",
            &format!("Complete ({}/{})", done, n),
        );
        if received.is_vulnerable {
            vulnerabilities.push(received);
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    print_status(&format!("Scan completed in {:.2} seconds", elapsed), Status::Info);
    print_status(&format!("Total parameters scanned: {}", n), Status::Info);
    print_status(
        &format!("Vulnerable parameters found: {}", vulnerabilities.len()),
        Status::Info,
    );

    for v in &vulnerabilities {
        print_status(
            &format!("  {} [{}] db={:?}", v.parameter, v.techniques.join(", "), v.database_type),
            Status::Vuln,
        );
    }

    if !vulnerabilities.is_empty() {
        if let Err(e) = crate::output::export_results(&config.url, &vulnerabilities) {
            print_status(&format!("Failed to export results: {}", e), Status::Error);
        }
    }

    vulnerabilities
}
