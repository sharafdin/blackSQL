//! Detection techniques - port of legacy/lib/techniques/
//! Each returns (vulnerable, db_type, payload).

mod error_based;
mod boolean_based;
mod time_based;
mod union_based;
mod extractor;

pub use error_based::scan_parameter as scan_error_based;
pub use boolean_based::scan_parameter as scan_boolean_based;
pub use time_based::scan_parameter as scan_time_based;
pub use union_based::scan_parameter as scan_union_based;
pub use extractor::{extract_all, ExtractionResults};

use std::collections::HashMap;

/// Result of a technique scan: (vulnerable, db_type, payload).
#[derive(Clone, Debug, Default)]
pub struct TechniqueResult {
    pub vulnerable: bool,
    pub db_type: Option<String>,
    pub payload: Option<String>,
}

impl TechniqueResult {
    pub fn not_vulnerable() -> Self {
        Self {
            vulnerable: false,
            db_type: None,
            payload: None,
        }
    }

    pub fn vulnerable(db_type: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            vulnerable: true,
            db_type: Some(db_type.into()),
            payload: Some(payload.into()),
        }
    }
}

/// Context passed to each technique: handler, URL, and optional POST data for the param.
pub struct ScanContext<'a> {
    pub url: &'a str,
    pub handler: &'a crate::http_client::RequestHandler,
    pub is_post: bool,
    pub data: Option<&'a HashMap<String, String>>,
}
