#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Error-based SQL injection detection
"""

import re
from ..utils.http_utils import inject_payload_in_url, RequestHandler
from ..utils.cli import print_status

# SQL error patterns for different database types
ERROR_PATTERNS = {
    'mysql': [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_',
        r'valid MySQL result',
        r'MySqlClient\.',
        r'MySQL Query fail',
        r'SQL syntax.*MariaDB server',
        r'mysqli_fetch_array\(.*\)',
        r'.*You have an error in your SQL syntax.*'
    ],
    'postgresql': [
        r'PostgreSQL.*ERROR',
        r'Warning.*\Wpg_',
        r'valid PostgreSQL result',
        r'Npgsql\.',
        r'PG::SyntaxError:',
        r'org\.postgresql\.util\.PSQLException'
    ],
    'mssql': [
        r'Driver.* SQL[\-\_\ ]*Server',
        r'OLE DB.* SQL Server',
        r'\bSQL Server[^&lt;&quot;]+Driver',
        r'Warning.*mssql_',
        r'\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}',
        r'System\.Data\.SqlClient\.SqlException',
        r'(?s)Exception.*\WSystem\.Data\.SqlClient\.',
        r'Unclosed quotation mark after the character string',
        r"'80040e14'",
        r'mssql_query\(\)'
    ],
    'oracle': [
        r'\bORA-[0-9][0-9][0-9][0-9]',
        r'Oracle error',
        r'Oracle.*Driver',
        r'Warning.*\Woci_',
        r'Warning.*\Wora_',
        r'oracle\.jdbc\.driver'
    ],
    'sqlite': [
        r'SQLite/JDBCDriver',
        r'SQLite\.Exception',
        r'System\.Data\.SQLite\.SQLiteException',
        r'Warning.*sqlite_',
        r'Warning.*SQLite3::',
        r'\[SQLITE_ERROR\]'
    ],
    'general': [
        r'SQL syntax.*',
        r'syntax error has occurred',
        r'incorrect syntax near',
        r'unexpected end of SQL command',
        r'Warning: (?:mysql|mysqli|pg|sqlite|oracle|mssql)',
        r'unclosed quotation mark after the character string',
        r'quoted string not properly terminated',
        r'SQL command not properly ended',
        r'Error: .*?near .*? line [0-9]+'
    ]
}


class ErrorBasedDetector:
    """Class to detect error-based SQL injections"""

    def __init__(self, url, request_handler, logger, vuln_logger=None):
        """
        Initialize error-based detector

        Args:
            url (str): Target URL
            request_handler (RequestHandler): HTTP request handler instance
            logger (logging.Logger): Logger instance
            vuln_logger (VulnerabilityLogger, optional): Vulnerability logger
        """
        self.url = url
        self.request_handler = request_handler
        self.logger = logger
        self.vuln_logger = vuln_logger

        # Compile regular expressions
        self.error_patterns = {}
        for db_type, patterns in ERROR_PATTERNS.items():
            self.error_patterns[db_type] = [re.compile(
                pattern, re.IGNORECASE) for pattern in patterns]

    def detect_errors(self, response_text):
        """
        Detect SQL errors in response text

        Args:
            response_text (str): HTTP response text

        Returns:
            tuple: (bool, str) - (is_vulnerable, database_type)
        """
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if pattern.search(response_text):
                    return True, db_type

        return False, None

    def scan_parameter(self, parameter, payloads, is_post=False, data=None):
        """
        Scan a parameter for error-based SQL injection

        Args:
            parameter (str): Parameter name to test
            payloads (list): List of payloads to test
            is_post (bool): Whether to test POST parameter
            data (dict, optional): POST data

        Returns:
            tuple: (bool, str, str) - (is_vulnerable, database_type, payload)
        """
        self.logger.info(
            f"Testing parameter '{parameter}' for error-based SQL injection")

        # Store original URL/data for comparison
        if is_post:
            original_data = data.copy()
            original_response = self.request_handler.post(
                self.url, data=original_data)
        else:
            original_response = self.request_handler.get(self.url)

        # Check for SQL errors in each payload
        for payload in payloads:
            try:
                if is_post:
                    # Modify POST data
                    test_data = data.copy()
                    test_data[parameter] = payload

                    # Send POST request
                    response = self.request_handler.post(
                        self.url, data=test_data)
                else:
                    # Inject payload into URL parameter
                    test_url = inject_payload_in_url(
                        self.url, parameter, payload)

                    # Send GET request
                    response = self.request_handler.get(test_url)

                # Check for SQL errors in response
                is_vulnerable, db_type = self.detect_errors(response.text)

                if is_vulnerable:
                    # Log vulnerability
                    print_status(
                        f"Parameter '{parameter}' is vulnerable to error-based SQL injection", "vuln")
                    print_status(
                        f"Database type: {db_type if db_type != 'general' else 'Unknown'}", "info")
                    print_status(f"Payload: {payload}", "info")

                    self.logger.warning(
                        f"Found error-based SQL injection in parameter '{parameter}' with payload: {payload}")

                    if self.vuln_logger:
                        self.vuln_logger.add_vulnerability(
                            url=self.url,
                            injection_type="Error-based",
                            parameter=parameter,
                            payload=payload,
                            database_type=db_type if db_type != 'general' else 'Unknown'
                        )

                    return True, db_type, payload

            except Exception as e:
                self.logger.error(f"Error testing payload {payload}: {str(e)}")
                continue

        print_status(
            f"Parameter '{parameter}' is not vulnerable to error-based SQL injection", "info")
        self.logger.info(
            f"No error-based SQL injection found in parameter '{parameter}'")

        return False, None, None
