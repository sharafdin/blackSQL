# blackSQL

An advanced SQL Injection scanner with support for Error-Based, Union-Based, Boolean-Based, and Time-Based detection techniques.

## Features

- Multiple SQL injection detection techniques:
  - Error-Based SQL Injection
  - Boolean-Based SQL Injection
  - Time-Based SQL Injection
  - Union-Based SQL Injection
- Multi-threaded scanning for faster results
- Database type detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Database enumeration (tables, columns, data)
- Colorized CLI output
- Structured logging (JSON/CSV)
- WAF bypass techniques

## Installation

```bash
git clone https://github.com/sharafdin/blackSQL.git
cd blackSQL
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python blacksql.py -u "http://example.com/page.php?id=1"
```

Advanced options:

```bash
python blacksql.py -u "http://example.com/page.php?id=1" --level 3 --threads 10 --dump
```

### Command Line Arguments

| Option          | Description                                         |
| --------------- | --------------------------------------------------- |
| `-u, --url`     | Target URL (e.g., http://example.com/page.php?id=1) |
| `-p, --params`  | Specify parameters to scan (e.g., 'id,page')        |
| `--data`        | POST data (e.g., 'id=1&page=2')                     |
| `-c, --cookies` | HTTP cookies (e.g., 'PHPSESSID=value; admin=0')     |
| `-t, --threads` | Number of threads (default: 5)                      |
| `--timeout`     | Connection timeout in seconds (default: 10.0)       |
| `--proxy`       | Use a proxy (e.g., 'http://127.0.0.1:8080')         |
| `--level`       | Scan level (1-3, higher = more tests)               |
| `--dump`        | Attempt to dump database tables when vulnerable     |
| `--batch`       | Never ask for user input, use the default behavior  |
| `-o, --output`  | Save scan results to a file (CSV/JSON)              |

## Examples

Scan a URL with a specific parameter:

```bash
python blacksql.py -u "http://example.com/page.php?id=1" -p "id"
```

Scan with POST data:

```bash
python blacksql.py -u "http://example.com/login.php" --data "username=admin&password=test"
```

Use a proxy and increase scan level:

```bash
python blacksql.py -u "http://example.com/page.php?id=1" --proxy "http://127.0.0.1:8080" --level 3
```

Dump database when vulnerabilities are found:

```bash
python blacksql.py -u "http://example.com/page.php?id=1" --dump
```

## Disclaimer

This tool is intended for legal security testing and educational purposes only. Do not use it against any website or system without proper authorization. The author is not responsible for any misuse or damage caused by this tool.

## License

MIT License 
blackSQL is an open-source package licensed under the [MIT License](LICENSE) 