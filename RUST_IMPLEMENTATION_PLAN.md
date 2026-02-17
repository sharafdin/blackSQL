# blackSQL: Port Python → Rust

Plan derived from **PYTHON_ANALYSIS.md**. Port only what exists in the Python codebase; no extra features.

---

## Scope (from analysis)

- **CLI:** `-u` (required), `-p`, `--data`, `-c`, `-t`, `--timeout`, `--proxy`, `--level`, `--dump`, `--batch`, `-o`.  
  - `-o` = **log file path** (Python does not use it for JSON/CSV).  
  - `--dump` = **boolean flag only**: when set, for each vulnerable parameter run DB enumeration (DBs, tables, columns, limited data) and attach to result; same JSON/CSV export, no separate dump file.
- **Output:** JSON/CSV only when there is ≥1 vulnerability; always `output/blacksql_results_{timestamp}.json` and `.csv`.
- **Detection:** Error-, Boolean-, Time-, Union-based; level 1/2/3 payload subsets; WAF detection + bypass; extraction only when `--dump`.

---

## Phase 1: Project scaffold & CLI

**Goal:** Binary that parses args, validates URL, prints banner, shows params to scan. No HTTP.

| Step | Task | Deliverable |
|------|------|-------------|
| 1.1 | `cargo init`, add deps (clap, reqwest, tokio, etc.) | `Cargo.toml` |
| 1.2 | CLI: `-u`, `-p`, `--data`, `-c`, `-t`, `--timeout`, `--proxy`, `--level`, `--dump`, `--batch`, `-o` | Same as Python (see analysis) |
| 1.3 | URL validation ← `legacy/lib/utils/validator.py` | Reject invalid URL, exit with message |
| 1.4 | Banner + colored status (banner text, [*]/[+]/[!]/[-]) | Same as `legacy/lib/utils/cli.py` |
| 1.5 | Param list: from URL query and/or `-p` and/or `--data` keys | Same as engine init |

**Done when:** `cargo run -- -u "http://example.com/page?id=1"` prints banner, validates URL, shows params, exits.

---

## Phase 2: HTTP client & request plumbing

**Goal:** GET/POST with params, cookies, proxy, timeout; inject payload into one parameter (URL or POST body).

| Step | Task | Deliverable |
|------|------|-------------|
| 2.1 | HTTP client: GET/POST, timeout, proxy, cookies, TLS verify=False | Port of `legacy/lib/utils/http_utils.py` RequestHandler |
| 2.2 | Build URL with query; build POST body; set one param to payload (GET = inject in URL; POST = copy data map, set param) | Same behavior as Python (inject_payload_in_url + data copy) |
| 2.3 | Parse cookies string and POST data string → maps | Same as `parse_cookies`, `parse_post_data` |
| 2.4 | Measure response time helper | Same as `measure_response_time` |

**Done when:** Can send GET and POST with one param replaced by payload; no detection yet.

---

## Phase 3: Payloads & WAF bypass

**Goal:** Same payload sets and WAF bypass as Python.

| Step | Task | Deliverable |
|------|------|-------------|
| 3.1 | Port from `legacy/lib/payloads/sql_payloads.py`: ERROR_BASED, BOOLEAN_BASED, TIME_BASED, UNION_BASED, DB_FINGERPRINT, WAF_BYPASS, EXTRACTION_PAYLOADS | `payloads` module |
| 3.2 | Port from `legacy/lib/payloads/waf_bypass.py`: random_case, add_comments, url_encode, char_encoding, add_whitespace; get_bypass_payloads(payload, count) | Same API and behavior |
| 3.3 | Level 1/2/3: same slice lengths and WAF variant counts as `Scanner.prepare_payloads()`; cap 100 after bypass | Same payload sets per level |

**Done when:** For any level and technique, payload set matches Python.

---

## Phase 4: Detection techniques

**Goal:** Four techniques; each returns (vulnerable, db_type, payload). Port from `legacy/lib/techniques/`.

| Step | Task | Deliverable |
|------|------|-------------|
| 4.1 | **Error-based** ← `error_based.py`: payloads → request; match body vs ERROR_PATTERNS (mysql, postgresql, mssql, oracle, sqlite, general) | (bool, Option<DbType>, payload) |
| 4.2 | **Boolean-based** ← `boolean_based.py`: TRUE/FALSE pairs; status/size/similarity < 0.95; DB from payload keywords | same |
| 4.3 | **Time-based** ← `time_based.py`: baseline 3 samples; delay >= baseline + 5*0.8, verify twice; DB from payload | same |
| 4.4 | **Union-based** ← `union_based.py`: ORDER BY column count; generate union payloads; detect number/version in response | same |

**Done when:** Each technique works for one parameter; no engine yet.

---

## Phase 5: Scanner engine & concurrency

**Goal:** One scan: all techniques per param, params in parallel. Port of `legacy/lib/core/engine.py`.

| Step | Task | Deliverable |
|------|------|-------------|
| 5.1 | Scanner config: url, params, data, cookies, threads, timeout, proxy, level, dump (bool), batch, logger | Same as `Scanner.__init__` |
| 5.2 | Per param: error → boolean → time; if vulnerable or level 3 → union; if vulnerable and dump → run extractor, attach extraction to result | Same order and conditions |
| 5.3 | Parallelize over parameters (rayon or tokio), min(threads, len(params)) workers | Same as Python threading |
| 5.4 | Progress: total/completed params, progress bar | Same as `progress_bar` in cli.py |
| 5.5 | WAF check at start; if WAF, ensure WAF bypass (re-prepare payloads) | Same as check_target + prepare_payloads |

**Done when:** `blacksql -u "http://...?id=1&page=2" --level 2` scans both params and reports vulnerabilities.

---

## Phase 6: Extraction (--dump)

**Goal:** When `--dump` is true and a param is vulnerable, run DB enumeration and attach to result. No separate dump file.

| Step | Task | Deliverable |
|------|------|-------------|
| 6.1 | Port `DatabaseExtractor` from `legacy/lib/techniques/extractor.py`: EXTRACTION_PAYLOADS per db type; extract_databases, extract_tables, extract_columns, extract_data; extract_content(payload) parses response | Same structure |
| 6.2 | extract_all(): databases → tables (first 2) → columns (first 3 tables) → data (first 3 cols); return extraction_results dict | Same limits as Python |
| 6.3 | Engine: if vulnerable and dump, call extractor, set result.extraction; export remains same JSON/CSV (vuln details include extraction) | Same as Python |

**Done when:** With `--dump`, vulnerable params get extraction in the same result/export.

---

## Phase 7: Output & logging

**Goal:** Log file (optional path from `-o`), VulnerabilityLogger, JSON/CSV only when vulns found.

| Step | Task | Deliverable |
|------|------|-------------|
| 7.1 | Logger: file (path from `-o` or `logs/blacksql_{timestamp}.log`), console at WARNING | Same as setup_logger |
| 7.2 | VulnerabilityLogger: add_vulnerability; export_to_json, export_to_csv | Same fields and schema |
| 7.3 | Engine: only if vulnerabilities non-empty → mkdir output, timestamp → `output/blacksql_results_{timestamp}.json` and `.csv` | Same as Python; `-o` is not used for these files |
| 7.4 | Stdout: duration, params scanned, vulnerable count; “Results exported to …” when applicable | Same UX |

**Done when:** Log goes to `-o` or default; JSON/CSV to output/ with timestamp when vulns exist.

---

## Phase 8: Polish & parity

**Goal:** Match Python behavior.

| Step | Task | Deliverable |
|------|------|-------------|
| 8.1 | Batch: no prompts (flag passed through; code has no prompts) | Same |
| 8.2 | Errors: invalid URL, connection, timeout → clear message, exit 1 | Same |
| 8.3 | Ctrl+C → “[!] Scan interrupted by user”, exit 0 | Same |
| 8.4 | Optional: tests for validator, payload selection, one technique | `cargo test` |

**Done when:** Rust binary matches Python behavior for single URL, GET/POST, four techniques, levels 1–3, WAF, `--dump` (boolean → extraction in result), `-o` (log path), JSON/CSV under output/.

---

## Crate layout (Rust)

```
src/
  main.rs           # CLI, banner, config, run scanner
  lib.rs            # pub use modules
  config.rs         # CLI args → ScanConfig
  validator.rs      # URL validation, extract_params, parse_cookies, parse_post_data  (← validator.py)
  http_client.rs    # RequestHandler, inject in URL, measure_response_time          (← http_utils.py)
  payloads/
    mod.rs
    sql_payloads.rs # ERROR_BASED, BOOLEAN_BASED, TIME_BASED, UNION_BASED,           (← sql_payloads.py)
                   # DB_FINGERPRINT, WAF_BYPASS, EXTRACTION_PAYLOADS
    waf_bypass.rs  # WAFBypass variants                                             (← waf_bypass.py)
  techniques/
    mod.rs
    error_based.rs  # ← error_based.py
    boolean_based.rs
    time_based.rs
    union_based.rs
    extractor.rs    # ← extractor.py (used only when --dump)
  engine.rs         # Scanner: params queue, workers, technique order, dump branch  (← engine.py)
  output.rs         # VulnerabilityLogger, export JSON/CSV                          (← logger.py)
  cli.rs            # Banner, ColorPrint, print_status, progress_bar                 (← cli.py)
  waf_detector.rs   # WAF_SIGNATURES, BLOCK_PATTERNS, detect, check_target           (← waf_detector.py)
```

---

## Execution order

1. Phase 1 → binary, CLI, validation, banner  
2. Phase 2 → HTTP + injection  
3. Phase 3 → payloads + WAF bypass  
4. Phase 4 → four techniques  
5. Phase 5 → engine + concurrency  
6. Phase 6 → --dump extraction (attach to result only)  
7. Phase 7 → logging, JSON/CSV to output/  
8. Phase 8 → polish, parity with Python  

After Phase 8 the current Python behavior is fully ported to Rust.
