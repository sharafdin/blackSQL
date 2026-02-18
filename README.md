# blackSQL

An advanced SQL Injection scanner with support for Error-Based, Union-Based, Boolean-Based, and Time-Based detection techniques.

The **Rust implementation** is the main version. The original Python implementation is kept in [`legacy/`](legacy/) for reference.

## Features

- Multiple SQL injection detection techniques:
  - Error-Based SQL Injection
  - Boolean-Based SQL Injection
  - Time-Based SQL Injection
  - Union-Based SQL Injection
- Multi-threaded scanning for faster results
- Database type detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Database enumeration (tables, columns, data) with `--dump`
- Colorized CLI output
- File logging (`-o` or `logs/blacksql_<timestamp>.log`) and JSON/CSV export to `output/`
- WAF detection and bypass techniques

## Installation

**From source (recommended):**

```bash
git clone https://github.com/sharafdin/blackSQL.git
cd blackSQL
cargo build --release
```

**Install the binary (after building):**

```bash
cargo install --path .
# Then run from anywhere:
blacksql -u "http://example.com/page.php?id=1"
```

**Legacy Python version:**

```bash
cd legacy
pip install -r requirements.txt
```

## Usage (Rust)

Basic scan:

```bash
./target/release/blacksql -u "http://example.com/page.php?id=1"
```

With options:

```bash
./target/release/blacksql -u "http://example.com/page.php?id=1" \
  --level 3 \
  --threads 10 \
  --dump \
  -o /path/to/scan.log
```

| Option            | Description |
|-------------------|-------------|
| `-u, --url`       | Target URL (required). |
| `-p, --params`    | Parameters to scan (e.g. `id,page`). Default: from URL or `--data`. |
| `--data`          | POST body (e.g. `id=1&page=2`) for POST-based scanning. |
| `-c, --cookies`   | Cookie string (e.g. `PHPSESSID=value; admin=0`). |
| `-t, --threads`   | Number of threads (default: 5). |
| `--timeout`       | Request timeout in seconds (default: 10.0). |
| `--proxy`         | Proxy URL (e.g. `http://127.0.0.1:8080`). |
| `--level`         | Scan depth 1–3 (default: 1). Higher = more payloads. |
| `--dump`          | When a parameter is vulnerable, enumerate DBs/tables/columns and include in results. |
| `--batch`         | Non-interactive (no prompts). |
| `-o, --output`    | **Log file path.** All scan messages are written here. If omitted, uses `logs/blacksql_<timestamp>.log`. JSON/CSV results are always written to `output/blacksql_results_<timestamp>.json` and `.csv` when vulnerabilities are found. |

**Output locations:**

- **Log file:** Path from `-o`, or `logs/blacksql_YYYYMMDD_HHMMSS.log`.
- **JSON/CSV (when vulns found):** `output/blacksql_results_YYYYMMDD_HHMMSS.json` and `.csv`.

### Examples (Rust)

Scan a specific parameter:

```bash
./target/release/blacksql -u "http://example.com/page.php?id=1" -p "id"
```

Scan with POST data:

```bash
./target/release/blacksql -u "http://example.com/login.php" --data "username=admin&password=test"
```

Use a proxy and higher level:

```bash
./target/release/blacksql -u "http://example.com/page.php?id=1" --proxy "http://127.0.0.1:8080" --level 3
```

Dump database info when vulnerable:

```bash
./target/release/blacksql -u "http://example.com/page.php?id=1" --dump
```

---

### Legacy Python usage

```bash
cd legacy && python blacksql.py -u "http://example.com/page.php?id=1"
```

See the table above for the same options; `-o` is the log file path in both versions.

## Disclaimer

This tool is intended for legal security testing and educational purposes only. Do not use it against any website or system without proper authorization. The author is not responsible for any misuse or damage caused by this tool.

## License

blackSQL is open-source under the [MIT License](LICENSE).
