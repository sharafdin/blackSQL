//! Payloads and WAF bypass - port of legacy/lib/payloads/

mod sql_payloads;
mod waf_bypass;

pub use sql_payloads::{
    db_fingerprint_mysql, db_fingerprint_mssql, db_fingerprint_oracle, db_fingerprint_postgres,
    db_fingerprint_sqlite, extraction_payloads_for_db, extraction_payloads_mysql,
    extraction_payloads_mssql, extraction_payloads_oracle, extraction_payloads_postgres,
    extraction_payloads_sqlite, ExtractionPayloads, ERROR_BASED, BOOLEAN_BASED, TIME_BASED,
    UNION_BASED, WAF_BYPASS,
};
pub use waf_bypass::{apply_waf_bypass, apply_bypass_technique, get_bypass_payloads};

/// Prepared payload sets per level (error, boolean, time, union). Same as Scanner.prepare_payloads().
#[derive(Clone, Default)]
pub struct PreparedPayloads {
    pub error: Vec<String>,
    pub boolean: Vec<String>,
    pub time: Vec<String>,
    pub union: Vec<String>,
}

const MAX_PAYLOADS_AFTER_BYPASS: usize = 100;

/// Build payload sets for the given level (1–3) and WAF bypass flag. Same as Python prepare_payloads.
pub fn prepare_payloads(level: u8, use_waf_bypass: bool) -> PreparedPayloads {
    let level = level.clamp(1, 3);

    let (error_slice, boolean_slice, time_slice, union_slice, err_waf, bool_waf, time_waf, union_waf) = match level {
        1 => (7, 6, 4, 0, 2, 2, 1, 0),
        2 => (15, 12, 10, 0, 3, 3, 2, 0),
        _ => (
            ERROR_BASED.len(),
            BOOLEAN_BASED.len(),
            TIME_BASED.len(),
            UNION_BASED.len(),
            5, 5, 3, 3,
        ),
    };

    let mut error: Vec<String> = ERROR_BASED.iter().take(error_slice).map(|s| (*s).to_string()).collect();
    let mut boolean: Vec<String> = BOOLEAN_BASED.iter().take(boolean_slice).map(|s| (*s).to_string()).collect();
    let mut time: Vec<String> = TIME_BASED.iter().take(time_slice).map(|s| (*s).to_string()).collect();
    let mut union: Vec<String> = UNION_BASED.iter().take(union_slice).map(|s| (*s).to_string()).collect();

    if use_waf_bypass {
        error = apply_waf_bypass(&error, err_waf, MAX_PAYLOADS_AFTER_BYPASS);
        boolean = apply_waf_bypass(&boolean, bool_waf, MAX_PAYLOADS_AFTER_BYPASS);
        time = apply_waf_bypass(&time, time_waf, MAX_PAYLOADS_AFTER_BYPASS);
        if union_waf > 0 {
            union = apply_waf_bypass(&union, union_waf, MAX_PAYLOADS_AFTER_BYPASS);
        }
    }

    PreparedPayloads {
        error,
        boolean,
        time,
        union,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_payloads_level1() {
        let p = prepare_payloads(1, false);
        assert_eq!(p.error.len(), 7);
        assert_eq!(p.boolean.len(), 6);
        assert_eq!(p.time.len(), 4);
        assert!(p.union.is_empty());
    }

    #[test]
    fn test_prepare_payloads_level2() {
        let p = prepare_payloads(2, false);
        assert_eq!(p.error.len(), 15);
        assert_eq!(p.boolean.len(), 12);
        assert_eq!(p.time.len(), 10);
        assert!(p.union.is_empty());
    }

    #[test]
    fn test_prepare_payloads_level3() {
        let p = prepare_payloads(3, false);
        assert_eq!(p.error.len(), ERROR_BASED.len());
        assert_eq!(p.boolean.len(), BOOLEAN_BASED.len());
        assert_eq!(p.time.len(), TIME_BASED.len());
        assert_eq!(p.union.len(), UNION_BASED.len());
    }

    #[test]
    fn test_prepare_payloads_waf_bypass_cap() {
        let p = prepare_payloads(3, true);
        assert!(p.error.len() <= MAX_PAYLOADS_AFTER_BYPASS);
        assert!(p.boolean.len() <= MAX_PAYLOADS_AFTER_BYPASS);
    }
}
