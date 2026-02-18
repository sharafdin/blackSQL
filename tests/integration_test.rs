//! Integration test: run scanner against a mock HTTP server that returns a MySQL error.
//! Verifies the engine detects error-based SQLi when the server responds with an error message.

use blacksql::engine::{run_scan, ScannerConfig};
use httpmock::prelude::*;
use std::collections::HashMap;

#[test]
fn scan_detects_error_based_injection() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.any_request();
        then.status(200)
            .body("You have an error in your SQL syntax near '1' at line 1");
    });

    let url = format!("http://{}/?id=1", server.address());
    let config = ScannerConfig {
        url,
        params: vec!["id".to_string()],
        data: HashMap::new(),
        cookies: HashMap::new(),
        threads: 1,
        timeout: 5.0,
        proxy: None,
        level: 1,
        dump: false,
        batch: true,
    };

    let vulnerabilities = run_scan(config);

    assert!(
        !vulnerabilities.is_empty(),
        "expected at least one vulnerability (error-based)"
    );
    assert_eq!(vulnerabilities[0].parameter, "id");
    assert!(vulnerabilities[0].techniques.iter().any(|t| t.contains("Error")));
}
