//! Time-based SQL injection detection - port of legacy/lib/techniques/time_based.py

use std::thread;
use std::time::Duration;

use crate::http_client::{inject_payload_in_url, measure_response_time_get, measure_response_time_post};
use super::{ScanContext, TechniqueResult};

const DELAY_THRESHOLD_SECS: f64 = 5.0;
const BASELINE_SAMPLES: usize = 3;
const BASELINE_SLEEP_MS: u64 = 500;
/// Delay considered significant: baseline + DELAY_THRESHOLD * 0.8
pub(crate) fn is_time_delayed(response_time: f64, baseline: f64) -> bool {
    response_time >= baseline + DELAY_THRESHOLD_SECS * 0.8
}

pub(crate) fn db_type_from_payload(payload: &str) -> String {
    let u = payload.to_uppercase();
    if u.contains("PG_SLEEP") {
        "PostgreSQL".to_string()
    } else if u.contains("WAITFOR DELAY") {
        "MSSQL".to_string()
    } else if u.contains("SLEEP") {
        "MySQL".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn calculate_baseline(ctx: &ScanContext) -> f64 {
    let mut times = Vec::with_capacity(BASELINE_SAMPLES);
    for _ in 0..BASELINE_SAMPLES {
        let data = ctx.data.map(|m| m.clone()).unwrap_or_default();
        let res = if ctx.is_post {
            measure_response_time_post(ctx.handler, ctx.url, &data)
        } else {
            measure_response_time_get(ctx.handler, ctx.url)
        };
        if let Ok((_, t)) = res {
            times.push(t);
        }
        thread::sleep(Duration::from_millis(BASELINE_SLEEP_MS));
    }
    if times.is_empty() {
        return 1.0;
    }
    times.iter().sum::<f64>() / times.len() as f64
}

/// Scan one parameter for time-based SQLi. Requires two delayed responses to confirm.
pub fn scan_parameter(
    ctx: &ScanContext,
    parameter: &str,
    payloads: &[String],
) -> TechniqueResult {
    let baseline = calculate_baseline(ctx);
    let data = ctx.data.map(|m| m.clone()).unwrap_or_default();

    for payload in payloads {
        let (response_time, test_data_opt) = if ctx.is_post {
            let mut form = data.clone();
            form.insert(parameter.to_string(), payload.clone());
            match measure_response_time_post(ctx.handler, ctx.url, &form) {
                Ok((_, t)) => (t, Some(form)),
                Err(_) => continue,
            }
        } else {
            let url = inject_payload_in_url(ctx.url, parameter, payload);
            match measure_response_time_get(ctx.handler, &url) {
                Ok((_, t)) => (t, None),
                Err(_) => continue,
            }
        };

        if !is_time_delayed(response_time, baseline) {
            continue;
        }

        // Verify with second request
        let verify_time = if ctx.is_post {
            let form = test_data_opt.unwrap();
            match measure_response_time_post(ctx.handler, ctx.url, &form) {
                Ok((_, t)) => t,
                Err(_) => continue,
            }
        } else {
            let url = inject_payload_in_url(ctx.url, parameter, payload);
            match measure_response_time_get(ctx.handler, &url) {
                Ok((_, t)) => t,
                Err(_) => continue,
            }
        };

        if is_time_delayed(verify_time, baseline) {
            let db = db_type_from_payload(payload);
            return TechniqueResult::vulnerable(db, payload.clone());
        }
    }

    TechniqueResult::not_vulnerable()
}

#[cfg(test)]
mod tests {
    use super::{db_type_from_payload, is_time_delayed};

    #[test]
    fn test_db_type_from_payload() {
        assert_eq!(db_type_from_payload("1 AND SLEEP(5)--"), "MySQL");
        assert_eq!(db_type_from_payload("1; PG_SLEEP(5)--"), "PostgreSQL");
        assert_eq!(db_type_from_payload("1; WAITFOR DELAY '0:0:5'--"), "MSSQL");
        assert_eq!(db_type_from_payload("1 AND 1=1"), "Unknown");
    }

    #[test]
    fn test_is_time_delayed() {
        let baseline = 0.5;
        assert!(is_time_delayed(4.5 + 0.1, baseline)); // >= baseline + 4.0
        assert!(!is_time_delayed(2.0, baseline));
    }
}
