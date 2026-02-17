//! URL and input validation - port of legacy/lib/utils/validator.py

use regex::Regex;
use std::collections::HashMap;

/// Python: r'^(?:http|https)://' + domain|localhost|ipv4 + optional port + path
static URL_PATTERN: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
    Regex::new(
        r"(?i)^(?:http|https)://(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/?|[/?]\S+)$",
    )
    .expect("valid URL regex")
});

/// Validate if a URL is properly formatted. Same as Python validate_url().
pub fn validate_url(url: &str) -> bool {
    URL_PATTERN.is_match(url.trim())
}

/// Extract query parameters from URL. Returns param name -> first value.
/// Same as Python extract_params().
pub fn extract_params_from_url(url: &str) -> HashMap<String, String> {
    let url = url.trim();
    let query = match url.find('?') {
        Some(i) => &url[i + 1..],
        None => return HashMap::new(),
    };
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let pair = pair.trim();
        if let Some(eq) = pair.find('=') {
            let key = urlencoding::decode(pair[..eq].trim()).unwrap_or_default();
            let val = urlencoding::decode(pair[eq + 1..].trim()).unwrap_or_default();
            if !params.contains_key(key.as_ref()) {
                params.insert(key.to_string(), val.to_string());
            }
        }
    }
    params
}

/// Parse cookie string (e.g. 'name=value; name2=value2') into map.
pub fn parse_cookies(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let s = s.trim();
    if s.is_empty() {
        return out;
    }
    for part in s.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim().to_string();
            let val = part[eq + 1..].trim().to_string();
            out.insert(key, val);
        }
    }
    out
}

/// Parse POST data string (e.g. 'id=1&page=2') into map. Same as parse_qsl.
pub fn parse_post_data(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let s = s.trim();
    if s.is_empty() {
        return out;
    }
    for part in s.split('&') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = urlencoding::decode(part[..eq].trim()).unwrap_or_default();
            let val = urlencoding::decode(part[eq + 1..].trim()).unwrap_or_default();
            out.insert(key.to_string(), val.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url() {
        assert!(validate_url("http://example.com/page?id=1"));
        assert!(validate_url("https://localhost/"));
        assert!(validate_url("http://192.168.1.1:8080/path"));
        assert!(!validate_url("ftp://example.com"));
        assert!(!validate_url("not-a-url"));
    }

    #[test]
    fn test_extract_params() {
        let p = extract_params_from_url("http://x.com?a=1&b=2");
        assert_eq!(p.get("a").map(String::as_str), Some("1"));
        assert_eq!(p.get("b").map(String::as_str), Some("2"));
    }

    #[test]
    fn test_parse_cookies() {
        let c = parse_cookies("session=abc; user=1");
        assert_eq!(c.get("session").map(String::as_str), Some("abc"));
        assert_eq!(c.get("user").map(String::as_str), Some("1"));
    }

    #[test]
    fn test_parse_post_data() {
        let d = parse_post_data("id=1&page=2");
        assert_eq!(d.get("id").map(String::as_str), Some("1"));
        assert_eq!(d.get("page").map(String::as_str), Some("2"));
    }
}
