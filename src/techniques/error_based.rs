//! Error-based SQL injection detection - port of legacy/lib/techniques/error_based.py

use once_cell::sync::Lazy;
use regex::RegexSet;
use std::collections::HashMap;

use crate::http_client::inject_payload_in_url;
use super::{ScanContext, TechniqueResult};

/// Order of DB types for matching (first match wins). general last.
const DB_ORDER: &[&str] = &["mysql", "postgresql", "mssql", "oracle", "sqlite", "general"];

/// Regex sets per DB type (case-insensitive). Built from Python ERROR_PATTERNS.
static ERROR_PATTERNS: Lazy<HashMap<&'static str, RegexSet>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let mysql = RegexSet::new([
        r"(?i)SQL syntax.*MySQL",
        r"(?i)Warning.*mysql_",
        r"(?i)valid MySQL result",
        r"(?i)MySqlClient\.",
        r"(?i)MySQL Query fail",
        r"(?i)SQL syntax.*MariaDB server",
        r"(?i)mysqli_fetch_array\(.*\)",
        r"(?i).*You have an error in your SQL syntax.*",
    ]).unwrap();
    m.insert("mysql", mysql);

    let postgresql = RegexSet::new([
        r"(?i)PostgreSQL.*ERROR",
        r"(?i)Warning.*\Wpg_",
        r"(?i)valid PostgreSQL result",
        r"(?i)Npgsql\.",
        r"(?i)PG::SyntaxError:",
        r"(?i)org\.postgresql\.util\.PSQLException",
    ]).unwrap();
    m.insert("postgresql", postgresql);

    let mssql = RegexSet::new([
        r"(?i)Driver.* SQL[\-\_\ ]*Server",
        r"(?i)OLE DB.* SQL Server",
        r"(?i)\bSQL Server[^&lt;&quot;]+Driver",
        r"(?i)Warning.*mssql_",
        r"(?i)\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"(?i)System\.Data\.SqlClient\.SqlException",
        r"(?is)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?i)Unclosed quotation mark after the character string",
        r"(?i)'80040e14'",
        r"(?i)mssql_query\(\)",
    ]).unwrap();
    m.insert("mssql", mssql);

    let oracle = RegexSet::new([
        r"(?i)\bORA-[0-9][0-9][0-9][0-9]",
        r"(?i)Oracle error",
        r"(?i)Oracle.*Driver",
        r"(?i)Warning.*\Woci_",
        r"(?i)Warning.*\Wora_",
        r"(?i)oracle\.jdbc\.driver",
    ]).unwrap();
    m.insert("oracle", oracle);

    let sqlite = RegexSet::new([
        r"(?i)SQLite/JDBCDriver",
        r"(?i)SQLite\.Exception",
        r"(?i)System\.Data\.SQLite\.SQLiteException",
        r"(?i)Warning.*sqlite_",
        r"(?i)Warning.*SQLite3::",
        r"(?i)\[SQLITE_ERROR\]",
    ]).unwrap();
    m.insert("sqlite", sqlite);

    let general = RegexSet::new([
        r"(?i)SQL syntax.*",
        r"(?i)syntax error has occurred",
        r"(?i)incorrect syntax near",
        r"(?i)unexpected end of SQL command",
        r"(?i)Warning: (?:mysql|mysqli|pg|sqlite|oracle|mssql)",
        r"(?i)unclosed quotation mark after the character string",
        r"(?i)quoted string not properly terminated",
        r"(?i)SQL command not properly ended",
        r"(?i)Error: .*?near .*? line [0-9]+",
    ]).unwrap();
    m.insert("general", general);

    m
});

pub(crate) fn detect_errors(response_text: &str) -> Option<&'static str> {
    for &db in DB_ORDER {
        if let Some(set) = ERROR_PATTERNS.get(db) {
            if set.is_match(response_text) {
                return Some(db);
            }
        }
    }
    None
}

/// Scan one parameter for error-based SQLi. Returns first vulnerable payload match.
pub fn scan_parameter(
    ctx: &ScanContext,
    parameter: &str,
    payloads: &[String],
) -> TechniqueResult {
    let data = ctx.data.map(|m| m.clone()).unwrap_or_default();

    for payload in payloads {
        let res = if ctx.is_post {
            let mut form = data.clone();
            form.insert(parameter.to_string(), payload.clone());
            ctx.handler.post(ctx.url, &form)
        } else {
            let url = inject_payload_in_url(ctx.url, parameter, payload);
            ctx.handler.get(&url)
        };

        let response = match res {
            Ok(r) => r,
            Err(_) => continue,
        };

        let text = match response.text() {
            Ok(t) => t,
            Err(_) => continue,
        };

        if let Some(db_type) = detect_errors(&text) {
            let db_display = if db_type == "general" {
                "Unknown".to_string()
            } else {
                db_type.to_string()
            };
            return TechniqueResult::vulnerable(db_display, payload.clone());
        }
    }

    TechniqueResult::not_vulnerable()
}

#[cfg(test)]
mod tests {
    use super::detect_errors;

    #[test]
    fn test_detect_errors_mysql() {
        assert_eq!(
            detect_errors("You have an error in your SQL syntax near 'x'"),
            Some("mysql")
        );
    }

    #[test]
    fn test_detect_errors_no_match() {
        assert_eq!(detect_errors("Hello world"), None);
    }
}
