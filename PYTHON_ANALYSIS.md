# Full Analysis: blackSQL Python Codebase (legacy/)

Analysis of the current Python implementation. No suggested or future features—only what exists in code.

---

## 1. Entry point & CLI

**File:** `legacy/blacksql.py`

- **Behavior:** Print banner → parse args → validate URL → setup logger → build Scanner → `scanner.start()`.
- **No URL:** Prints help and exits if no args; if URL missing after parse, red error and exit 1.
- **KeyboardInterrupt:** Yellow “[!] Scan interrupted by user”, exit 0.
- **Other exceptions:** Red error message, log, exit 1.

### CLI arguments (exactly as implemented)

| Arg | Type | Default | Usage in code |
|-----|------|---------|----------------|
| `-u, --url` | string | (required) | Target URL. Required; validated with `validate_url()`. |
| `-p, --params` | string | None | Comma-separated param names. Passed as `params.split(',')` if set. |
| `--data` | string | None | POST body string (e.g. `id=1&page=2`). Passed to Scanner as `data`. |
| `-c, --cookies` | string | None | Cookie string. Passed to Scanner as `cookies`. |
| `-t, --threads` | int | 5 | Scanner thread count. |
| `--timeout` | float | 10.0 | Request timeout in seconds. |
| `--proxy` | string | None | Proxy URL (e.g. `http://127.0.0.1:8080`). |
| `--level` | int | 1 | Choices 1, 2, 3. Scan depth (payload subset). |
| `--dump` | flag | False | **Boolean only.** When True, for each vulnerable parameter the engine runs DB enumeration (databases, tables, columns, limited data) and attaches it to the result. No separate dump file; extraction is included in vuln details and in the same JSON/CSV export. |
| `--batch` | flag | False | “Never ask for user input.” No prompts in code; flag is passed through only. |
| `-o, --output` | string | None | **Log file path.** Passed to `setup_logger(args.output)`. JSON/CSV are **not** written to this path; they are always `output/blacksql_results_{timestamp}.json` and `.csv`. |

So: `--dump` is a help-style boolean (“attempt to dump when vulnerable”); `-o` is for the log file, not the result files.

---

## 2. Validator

**File:** `legacy/lib/utils/validator.py`

- **validate_url(url):** Regex: `(http|https)://`, then (domain | localhost | IPv4), optional port, optional path/query. Returns bool.
- **extract_params(url):** `urlparse` + `parse_qs`; returns dict param → value (single value per key).
- **parse_cookies(s):** Split by `;`, then `=`, strip; returns dict.
- **parse_post_data(s):** `parse_qsl`; returns dict.

---

## 3. HTTP

**File:** `legacy/lib/utils/http_utils.py`

- **RequestHandler:** Session with User-Agent, optional proxy (`http`/`https`), optional cookies, `verify=False`, `allow_redirects=True`. `get(url, params=..., additional_headers=...)`, `post(url, data=..., json=..., additional_headers=...)`. Timeout from init.
- **inject_payload_in_url(url, parameter, payload):** Parse query, set or add `parameter` to `payload`, rebuild URL.
- **measure_response_time(func, *args, **kwargs):** Call func, return `(response, elapsed_seconds)`.

No `inject_payload_in_data` function; POST injection is done by copying `data` and setting `data[parameter] = payload` at call sites.

---

## 4. CLI output

**File:** `legacy/lib/utils/cli.py`

- **ColorPrint:** red, green, yellow, blue, magenta, cyan, bold (colorama).
- **print_banner():** Red “blackSQL” ASCII, cyan “[*]” lines (author, version 1.0.0).
- **print_status(msg, status):** success=green [+], info=blue [*], warning=yellow [!], error=red [-], vuln=red [VULNERABLE].
- **progress_bar(iteration, total, prefix, suffix, length=50, fill='█'):** Single-line progress bar; newline when iteration == total.

---

## 5. Logging

**File:** `legacy/lib/utils/logger.py`

- **setup_logger(output_file=None):** Creates `logs/` if needed. Log file: `output_file` or `logs/blacksql_{timestamp}.log`. File handler INFO; console handler WARNING. Formatter: `%(asctime)s - %(levelname)s - %(message)s`. Returns logger.
- **VulnerabilityLogger:** Holds list `vulnerabilities`. `add_vulnerability(url, injection_type, parameter, payload, database_type=None, details=None)` appends dict with timestamp, url, injection_type, parameter, payload, database_type, details. `export_to_json(filename)` / `export_to_csv(filename)` write that list (JSON with scan_date and total_vulnerabilities; CSV with fixed fieldnames). Creates parent dir of filename if needed.

---

## 6. WAF detection

**File:** `legacy/lib/utils/waf_detector.py`

- **WAF_SIGNATURES:** Dict of WAF name → list of regex patterns (Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5, Sucuri, Barracuda, Fortinet, Citrix).
- **BLOCK_PATTERNS:** List of block-message regexes.
- **detect(response):** Check status in {403, 406, 429, 503} + block pattern in content → Generic WAF. Else check headers and content against WAF_SIGNATURES; return (True, waf_name) or (False, None).
- **check_target(request_handler, url, logger):** GET url → detect. If not WAF, GET again with `?sql=...` or `&sql=...` (suspicious param) → detect. Logs and print_status; returns (bool, waf_name or None).

---

## 7. Payloads

**File:** `legacy/lib/payloads/sql_payloads.py`

- **ERROR_BASED:** List of 31 strings (quotes, OR 1=1, ORDER BY, UNION, error-based extracts).
- **BOOLEAN_BASED:** List of 20 (AND/OR 1=1/1=0, quoted, dual, etc.).
- **TIME_BASED:** List of 18 (SLEEP, WAITFOR DELAY, pg_sleep, etc.).
- **UNION_BASED:** List of 20 (UNION SELECT NULL…, BANNER, @@version, version(), number sequences).
- **DB_FINGERPRINT:** Dict mysql/mssql/postgres/oracle/sqlite → list of payloads.
- **WAF_BYPASS:** List of strings (comments, case, whitespace, encoding, CHAR, null byte, logic, etc.) used as building blocks.
- **EXTRACTION_PAYLOADS:** Dict by db type → `databases`, `tables`, `columns`, `data` lists (with `{}` / `{0}` `{1}` placeholders for extractor).

**File:** `legacy/lib/payloads/waf_bypass.py`

- **WAFBypass:** `random_case`, `add_comments`, `url_encode` (optional double), `char_encoding`, `add_whitespace`, `apply_bypass_technique(payload, technique?)`, `get_bypass_payloads(payload, count=3)` → [original, ...variants] (random techniques, no duplicates).

---

## 8. Engine payload selection (level)

**File:** `legacy/lib/core/engine.py` — `prepare_payloads()`

- **Level 1:** error[:7], boolean[:6], time[:4], union=[]; WAF bypass variants: 2,2,1 per list; cap 100 total after bypass.
- **Level 2:** error[:15], boolean[:12], time[:10], union=[]; WAF variants 3,3,2.
- **Level 3:** full error, boolean, time, union; WAF variants 5,5,3,3.
- Original payloads always included; then bypass variants added; if len > 100, trim to 100.

---

## 9. Detection techniques

All receive (url, request_handler, logger, vuln_logger), and use inject_payload_in_url or POST data copy for injection.

- **Error-based** (`error_based.py`): For each payload, GET or POST with payload; match response body against ERROR_PATTERNS (mysql, postgresql, mssql, oracle, sqlite, general). First match → (True, db_type, payload); else (False, None, None). Logs and vuln_logger.add_vulnerability.
- **Boolean-based** (`boolean_based.py`): Pairs of payloads (i, i+1) as TRUE/FALSE. Compare responses: status code, size ratio < 0.7, or content similarity < 0.95 (after normalizing times, dates, hashes, whitespace). DB type from payload keywords. Returns (bool, db_type, payload).
- **Time-based** (`time_based.py`): Baseline = average of 3 GET/POST (no payload). For each payload, measure time; if >= baseline + 5*0.8 and second request also delayed → vulnerable. DB from payload (SLEEP→MySQL, PG_SLEEP→Postgres, WAITFOR→MSSQL). Returns (bool, db_type, payload).
- **Union-based** (`union_based.py`): `determine_column_count` with ORDER BY 1..20; error keywords → column count = i-1. Then `generate_union_payloads(column_count)` (number sequence, @@version/version()/banner in each column, info_schema/sysdatabases/pg_database). Test each; detect_injection_in_response with number-sequence and version regexes. DB from response content. Returns (bool, db_type, payload).

---

## 10. Extractor (used only when --dump is True)

**File:** `legacy/lib/techniques/extractor.py`

- **DatabaseExtractor(url, parameter, db_type, request_handler, logger, vuln_logger, is_post, data):** Chooses EXTRACTION_PAYLOADS by db_type (mysql/mssql/postgres/oracle/sqlite; default mysql).
- **extract_content(payload):** Inject payload (GET or POST), parse response (tags, db_output_patterns, or first 1000 chars).
- **extract_databases / extract_tables(db) / extract_columns(table) / extract_data(table, columns):** Use extraction payloads with placeholders; return first non-empty result per category.
- **extract_all():** databases → tables (first 2 DBs) → columns (first 3 tables) → data (first 3 cols); writes extraction_results into vuln_logger entry for this url+parameter.

So `--dump` is only a boolean: “when vulnerable, run enumeration and attach to vuln details.” No separate dump file.

---

## 11. Scanner engine flow

**File:** `legacy/lib/core/engine.py`

- **Init:** Parse data and cookies; build RequestHandler, VulnerabilityLogger; if no params, extract_params(url) + POST keys; prepare_payloads(); vulnerabilities = [].
- **start():** If no params → warning and return. WAF check (check_target); if WAF, re-prepare payloads. Dedupe params. Progress total = len(params), completed = 0. Queue of params; N worker threads (min(threads, len(params))) calling scan_parameter. Each scan_parameter: error → boolean → time → if vulnerable or level==3 then union → if vulnerable and dump then DatabaseExtractor.extract_all() and set results['extraction']. Push result to queue; progress_bar. Collect from queue into vulnerabilities. Print summary (duration, total params, vulnerable count). If vulnerabilities: mkdir output, timestamp, export_to_json/csv to output/, print success paths. Return vulnerabilities.

Vuln result shape per parameter: parameter, is_vulnerable, techniques[], database_type, optional extraction (if dump).

---

## 12. Output files (actual behavior)

- **Log:** From setup_logger: either `-o` path or `logs/blacksql_{timestamp}.log`.
- **JSON/CSV:** Always `output/blacksql_results_{timestamp}.json` and `.csv`. Only written when there is at least one vulnerability. Content = VulnerabilityLogger (vulns with details; when --dump was used, details include extraction_results).

---

## 13. Dependencies

**File:** `legacy/requirements.txt`

- requests, colorama, urllib3, certifi, charset-normalizer, idna.

---

## 14. Summary: what to port

- CLI: -u (required), -p, --data, -c, -t, --timeout, --proxy, --level, --dump (boolean), --batch, -o (log path).
- URL validation and param/cookie/POST parsing.
- HTTP: GET/POST, inject in URL or POST body, proxy, timeout, verify=False, measure_response_time.
- Banner and colored status/progress.
- Logger: file (+ optional -o), console WARNING; VulnerabilityLogger with add + export JSON/CSV.
- WAF: signatures + block patterns, check_target (normal + suspicious request).
- Payloads: error, boolean, time, union, DB_FINGERPRINT, WAF_BYPASS list, EXTRACTION_PAYLOADS; WAFBypass variants (random_case, comments, url_encode, char_encoding, whitespace).
- Level 1/2/3 payload subsets and WAF variant counts and 100-payload cap.
- Four techniques: error, boolean (TRUE/FALSE pairs, similarity 0.95), time (baseline + 5*0.8), union (ORDER BY column count, union payloads, response patterns).
- Engine: param queue, worker threads, order error→boolean→time→(union if vuln or level 3), then if vulnerable and dump run extractor and attach extraction.
- Export: only when vulns; JSON + CSV under output/ with timestamp; -o is log file only.
- --dump: boolean flag only; enables enumeration and adds extraction to vuln details in the same export.
