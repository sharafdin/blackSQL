//! HTTP client and request helpers - port of legacy/lib/utils/http_utils.py

use reqwest::blocking::{Client, Response};
use std::collections::HashMap;
use std::time::{Duration, Instant};


const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

/// HTTP request handler: GET/POST with timeout, proxy, cookies, TLS verify=false.
/// Same as Python RequestHandler.
pub struct RequestHandler {
    client: Client,
    cookie_header: Option<String>,
}

impl RequestHandler {
    /// Build a new handler. timeout in seconds; proxy optional; cookies as map.
    pub fn new(
        timeout_secs: f64,
        proxy: Option<&str>,
        user_agent: Option<&str>,
        cookies: &HashMap<String, String>,
    ) -> Result<Self, reqwest::Error> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs_f64(timeout_secs))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::default())
            .user_agent(user_agent.unwrap_or(DEFAULT_USER_AGENT));

        if let Some(p) = proxy {
            builder = builder.proxy(reqwest::Proxy::all(p)?);
        }

        let client = builder.build()?;

        let cookie_header = if cookies.is_empty() {
            None
        } else {
            Some(
                cookies
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        };

        Ok(Self {
            client,
            cookie_header,
        })
    }

    /// Convenience: timeout, optional proxy, cookies (same as Python engine).
    pub fn with_cookies(
        timeout_secs: f64,
        proxy: Option<&str>,
        cookies: &HashMap<String, String>,
    ) -> Result<Self, reqwest::Error> {
        Self::new(timeout_secs, proxy, None, cookies)
    }

    fn add_cookies(&self, mut req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        if let Some(ref h) = self.cookie_header {
            req = req.header("Cookie", h.as_str());
        }
        req
    }

    /// Send GET to url.
    pub fn get(&self, url: &str) -> Result<Response, reqwest::Error> {
        let req = self.client.get(url);
        self.add_cookies(req).send()
    }

    /// Send POST with form data (application/x-www-form-urlencoded). Same as Python post(url, data=...).
    pub fn post(&self, url: &str, data: &HashMap<String, String>) -> Result<Response, reqwest::Error> {
        let req = self.client.post(url).form(data);
        self.add_cookies(req).send()
    }

    /// POST with one parameter overridden to payload (for injection).
    pub fn post_with_injected_param(
        &self,
        url: &str,
        data: &HashMap<String, String>,
        parameter: &str,
        payload: &str,
    ) -> Result<Response, reqwest::Error> {
        let mut form = data.clone();
        form.insert(parameter.to_string(), payload.to_string());
        self.post(url, &form)
    }
}

/// Inject a payload into one URL query parameter. Same as Python inject_payload_in_url().
/// Returns the new URL with the parameter set to payload (added if missing).
pub fn inject_payload_in_url(url: &str, parameter: &str, payload: &str) -> String {
    let url = url.trim();
    let (base, query) = match url.find('?') {
        Some(i) => (&url[..i], &url[i + 1..]),
        None => return format!("{}?{}={}", url, parameter, urlencoding::encode(payload)),
    };

    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query.split('&') {
        let pair = pair.trim();
        if let Some(eq) = pair.find('=') {
            let k = urlencoding::decode(pair[..eq].trim()).unwrap_or_default();
            let v = urlencoding::decode(pair[eq + 1..].trim()).unwrap_or_default();
            params.insert(k.to_string(), v.to_string());
        }
    }
    params.insert(parameter.to_string(), payload.to_string());

    let query_str: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect();
    format!("{}?{}", base, query_str.join("&"))
}

/// Measure response time of a blocking GET. Returns (response, elapsed_secs).
/// Same as Python measure_response_time() for GET.
pub fn measure_response_time_get(
    handler: &RequestHandler,
    url: &str,
) -> Result<(Response, f64), reqwest::Error> {
    let start = Instant::now();
    let res = handler.get(url)?;
    let elapsed = start.elapsed().as_secs_f64();
    Ok((res, elapsed))
}

/// Measure response time of a blocking POST. Returns (response, elapsed_secs).
pub fn measure_response_time_post(
    handler: &RequestHandler,
    url: &str,
    data: &HashMap<String, String>,
) -> Result<(Response, f64), reqwest::Error> {
    let start = Instant::now();
    let res = handler.post(url, data)?;
    let elapsed = start.elapsed().as_secs_f64();
    Ok((res, elapsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_payload_in_url() {
        let u = "http://example.com/page?id=1&foo=bar";
        let out = inject_payload_in_url(u, "id", "' OR 1=1 --");
        assert!(out.contains("id="));
        assert!(out.contains("foo=bar"));
        // Payload is encoded (quote, space, =)
        assert!(out.contains("OR"));
        assert!(out.contains("1"));
        assert!(out.contains("--"));
    }

    #[test]
    fn test_inject_payload_adds_param() {
        let u = "http://example.com/page";
        let out = inject_payload_in_url(u, "id", "1");
        assert_eq!(out, "http://example.com/page?id=1");
    }

    /// Phase 2 "done when": GET with injected param. Run with: cargo test -- --ignored
    #[test]
    #[ignore]
    fn test_real_get_with_injected_param() {
        let handler = RequestHandler::with_cookies(10.0, None, &HashMap::new()).unwrap();
        let url = inject_payload_in_url("https://httpbin.org/get?id=1", "id", "' OR 1=1 --");
        let res = handler.get(&url).unwrap();
        assert!(res.status().is_success());
    }
}
