//! Boolean-based SQL injection detection - port of legacy/lib/techniques/boolean_based.py

use regex::Regex;

use crate::http_client::inject_payload_in_url;
use super::{ScanContext, TechniqueResult};

const SIMILARITY_THRESHOLD: f64 = 0.95;
const SIZE_RATIO_THRESHOLD: f64 = 0.7;

/// Normalize content: strip times, dates, hashes, collapse whitespace (same as Python).
fn normalize_content(content: &str) -> String {
    let time_re = Regex::new(r"\d{2}:\d{2}:\d{2}").unwrap();
    let date_re = Regex::new(r"\d{2}/\d{2}/\d{4}").unwrap();
    let md5_re = Regex::new(r"[a-fA-F0-9]{32}").unwrap();
    let sha1_re = Regex::new(r"[a-fA-F0-9]{40}").unwrap();
    let sha256_re = Regex::new(r"[a-fA-F0-9]{64}").unwrap();
    let ws_re = Regex::new(r"\s+").unwrap();

    let s = time_re.replace_all(content, "");
    let s = date_re.replace_all(&s, "");
    let s = md5_re.replace_all(&s, "");
    let s = sha1_re.replace_all(&s, "");
    let s = sha256_re.replace_all(&s, "");
    let s = ws_re.replace_all(&s, " ");
    s.trim().to_string()
}

/// Similarity ratio 0.0..1.0 (same as Python difflib.SequenceMatcher.ratio).
/// Use 1 - normalized OSA distance.
fn content_similarity(a: &str, b: &str) -> f64 {
    let na = normalize_content(a);
    let nb = normalize_content(b);
    if na.is_empty() && nb.is_empty() {
        return 1.0;
    }
    if na.is_empty() || nb.is_empty() {
        return 0.0;
    }
    let d = strsim::osa_distance(&na, &nb);
    let max_len = na.len().max(nb.len()) as f64;
    if max_len == 0.0 {
        return 1.0;
    }
    1.0 - (d as f64 / max_len)
}

fn has_significant_difference(
    true_text: &str,
    false_text: &str,
    true_status: u16,
    false_status: u16,
) -> bool {
    if true_status != false_status {
        return true;
    }
    let true_len = true_text.len();
    let false_len = false_text.len();
    let max_len = true_len.max(false_len);
    if max_len == 0 {
        return false;
    }
    let size_ratio = true_len.min(false_len) as f64 / max_len as f64;
    if size_ratio < SIZE_RATIO_THRESHOLD {
        return true;
    }
    content_similarity(true_text, false_text) < SIMILARITY_THRESHOLD
}

/// Infer DB type from payload keywords (same as Python).
fn db_type_from_payload(payload: &str) -> String {
    let u = payload.to_uppercase();
    if u.contains("MYSQL") || u.contains("SLEEP") || u.contains("INFORMATION_SCHEMA") {
        "MySQL".to_string()
    } else if u.contains("MSSQL") || u.contains("WAITFOR") || u.contains("SYSOBJECTS") {
        "MSSQL".to_string()
    } else if u.contains("PG_") || u.contains("POSTGRES") {
        "PostgreSQL".to_string()
    } else if u.contains("ORA") || u.contains("ROWNUM") {
        "Oracle".to_string()
    } else if u.contains("SQLITE") {
        "SQLite".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Scan one parameter: TRUE/FALSE payload pairs (i, i+1). Returns first pair that shows significant difference.
pub fn scan_parameter(
    ctx: &ScanContext,
    parameter: &str,
    payloads: &[String],
) -> TechniqueResult {
    let data = ctx.data.map(|m| m.clone()).unwrap_or_default();

    let pairs: Vec<_> = payloads
        .chunks(2)
        .filter_map(|c| {
            if c.len() == 2 {
                Some((c[0].as_str(), c[1].as_str()))
            } else {
                None
            }
        })
        .collect();

    for (true_payload, false_payload) in pairs {
        let (true_res, false_res) = if ctx.is_post {
            let mut t_data = data.clone();
            t_data.insert(parameter.to_string(), true_payload.to_string());
            let mut f_data = data.clone();
            f_data.insert(parameter.to_string(), false_payload.to_string());
            let tr = ctx.handler.post(ctx.url, &t_data);
            let fr = ctx.handler.post(ctx.url, &f_data);
            (tr, fr)
        } else {
            let t_url = inject_payload_in_url(ctx.url, parameter, true_payload);
            let f_url = inject_payload_in_url(ctx.url, parameter, false_payload);
            let tr = ctx.handler.get(&t_url);
            let fr = ctx.handler.get(&f_url);
            (tr, fr)
        };

        let (true_res, false_res) = match (true_res, false_res) {
            (Ok(a), Ok(b)) => (a, b),
            _ => continue,
        };

        let true_status = true_res.status().as_u16();
        let false_status = false_res.status().as_u16();
        let true_text = true_res.text().unwrap_or_default();
        let false_text = false_res.text().unwrap_or_default();

        if has_significant_difference(&true_text, &false_text, true_status, false_status) {
            let db = db_type_from_payload(true_payload);
            return TechniqueResult::vulnerable(db, true_payload.to_string());
        }
    }

    TechniqueResult::not_vulnerable()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_similarity_identical() {
        assert!((content_similarity("hello", "hello") - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_content_similarity_different() {
        assert!(content_similarity("abc", "xyz") < 0.5);
    }

    #[test]
    fn test_db_type_from_payload() {
        assert_eq!(db_type_from_payload("' AND SLEEP(5)"), "MySQL");
        assert_eq!(db_type_from_payload("x WAITFOR DELAY y"), "MSSQL");
    }
}
