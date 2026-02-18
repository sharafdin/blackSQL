//! WAF detection - port of legacy/lib/utils/waf_detector.py

use regex::RegexSet;
use crate::http_client::RequestHandler;
use crate::cli::{print_status, Status};

static BLOCK_PATTERNS: once_cell::sync::Lazy<RegexSet> = once_cell::sync::Lazy::new(|| {
    RegexSet::new([
        r"(?i)blocked",
        r"(?i)blocked by firewall",
        r"(?i)security policy",
        r"(?i)access denied",
        r"(?i)forbidden",
        r"(?i)illegal",
        r"(?i)unauthorized",
        r"(?i)suspicious activity",
        r"(?i)detected an attack",
        r"(?i)security rule",
        r"(?i)malicious",
        r"(?i)security violation",
        r"(?i)attack detected",
        r"(?i)automated request",
        r"(?i)your request has been blocked",
        r"(?i)your IP has been blocked",
        r"(?i)security challenge",
        r"(?i)challenge required",
        r"(?i)captcha",
        r"(?i)protection system",
    ]).unwrap()
});

/// WAF name -> list of signature patterns (subset for detection)
const WAF_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cloudflare", "cloudflare-nginx", "cf-ray", "CF-WAF"]),
    ("AWS WAF", &["aws-waf", "x-amzn-waf", "x-amz-cf-id"]),
    ("ModSecurity", &["mod_security", "modsecurity", "NOYB"]),
    ("Akamai", &["akamai", "akamaighost"]),
    ("Imperva/Incapsula", &["incapsula", "imperva", "incap_ses", "visid_incap"]),
    ("F5 BIG-IP", &["BigIP", "F5", "BIGipServer"]),
    ("Sucuri", &["sucuri", "cloudproxy"]),
    ("Barracuda", &["barracuda"]),
    ("Fortinet", &["fortigate", "fortiweb", "fortinet"]),
    ("Citrix NetScaler", &["netscaler", "ns_af=", "citrix_ns"]),
];

fn detect(response_status: u16, headers: &str, content: &str) -> Option<&'static str> {
    if [403, 406, 429, 503].contains(&response_status) && BLOCK_PATTERNS.is_match(content) {
        return Some("Generic WAF");
    }
    let combined = format!("{} {}", headers, content).to_lowercase();
    for (waf_name, patterns) in WAF_SIGNATURES {
        for &pat in *patterns {
            if combined.contains(&pat.to_lowercase()) {
                return Some(waf_name);
            }
        }
    }
    None
}

/// Check if target has WAF. Same as Python check_target. Returns (is_waf, waf_name).
pub fn check_target(handler: &RequestHandler, url: &str) -> (bool, Option<String>) {
    let normal = match handler.get(url) {
        Ok(r) => r,
        Err(_) => return (false, None),
    };
    let status = normal.status().as_u16();
    let headers: String = normal.headers().iter()
        .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join(" ");
    let content = normal.text().unwrap_or_default();
    if let Some(name) = detect(status, &headers, &content) {
        print_status(&format!("WAF detected: {}", name), Status::Warning);
        print_status("WAF bypassing techniques will be used", Status::Info);
        return (true, Some(name.to_string()));
    }
    let test_url = if url.contains('?') {
        format!("{}&sql=1%27%20OR%20%271%27%3D%271", url)
    } else {
        format!("{}?sql=1%27%20OR%20%271%27%3D%271", url)
    };
    let suspicious = match handler.get(&test_url) {
        Ok(r) => r,
        Err(_) => {
            print_status("No WAF detected on target", Status::Info);
            return (false, None);
        }
    };
    let status2 = suspicious.status().as_u16();
    let headers2: String = suspicious.headers().iter()
        .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join(" ");
    let content2 = suspicious.text().unwrap_or_default();
    if let Some(name) = detect(status2, &headers2, &content2) {
        print_status(&format!("WAF detected when sending suspicious request: {}", name), Status::Warning);
        print_status("WAF bypassing techniques will be used", Status::Info);
        return (true, Some(name.to_string()));
    }
    print_status("No WAF detected on target", Status::Info);
    (false, None)
}
