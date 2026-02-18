//! Export scan results to JSON/CSV - port of legacy/lib/utils/logger.py (VulnerabilityLogger export)

use std::fs;
use std::path::Path;

use chrono::Utc;
use serde::Serialize;

use crate::engine::ParamResult;

/// One vulnerability record for export (same schema as Python).
#[derive(Serialize)]
struct VulnRecord {
    timestamp: String,
    url: String,
    injection_type: String,
    parameter: String,
    payload: String,
    database_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Details>,
}

#[derive(Serialize)]
struct Details {
    #[serde(skip_serializing_if = "Option::is_none")]
    extraction_results: Option<serde_json::Value>,
}

/// Export vulnerabilities to JSON and CSV in output/ with timestamp. Prints paths. Same as Python engine.
pub fn export_results(url: &str, vulnerabilities: &[ParamResult]) -> Result<(), std::io::Error> {
    if vulnerabilities.is_empty() {
        return Ok(());
    }

    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let dir = Path::new("output");
    fs::create_dir_all(dir)?;

    let json_path = dir.join(format!("blacksql_results_{}.json", timestamp));
    let csv_path = dir.join(format!("blacksql_results_{}.csv", timestamp));

    let records: Vec<VulnRecord> = vulnerabilities
        .iter()
        .map(|v| VulnRecord {
            timestamp: Utc::now().to_rfc3339(),
            url: url.to_string(),
            injection_type: v.techniques.join(", "),
            parameter: v.parameter.clone(),
            payload: "-".to_string(),
            database_type: v.database_type.clone(),
            details: v.extraction.as_ref().map(|e| Details {
                extraction_results: Some(serde_json::to_value(e).unwrap_or(serde_json::Value::Null)),
            }),
        })
        .collect();

    let wrapper = serde_json::json!({
        "scan_date": Utc::now().to_rfc3339(),
        "total_vulnerabilities": records.len(),
        "vulnerabilities": records
    });
    fs::write(&json_path, serde_json::to_string_pretty(&wrapper).unwrap_or_default())?;

    // CSV: timestamp, url, injection_type, parameter, payload, database_type
    let mut csv = String::from("timestamp,url,injection_type,parameter,payload,database_type\n");
    for r in &records {
        let row = format!(
            "{},{},{},{},{},{}\n",
            r.timestamp,
            escape_csv(&r.url),
            escape_csv(&r.injection_type),
            escape_csv(&r.parameter),
            escape_csv(&r.payload),
            r.database_type.as_deref().unwrap_or("")
        );
        csv.push_str(&row);
    }
    fs::write(&csv_path, csv)?;

    crate::cli::print_status(
        &format!("Results exported to JSON: {}", json_path.display()),
        crate::cli::Status::Success,
    );
    crate::cli::print_status(
        &format!("Results exported to CSV: {}", csv_path.display()),
        crate::cli::Status::Success,
    );
    Ok(())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
