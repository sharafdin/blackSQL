#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core scanning engine for blackSQL
"""

import concurrent.futures
import time
import os
from urllib.parse import parse_qsl, urlparse

from ..utils.http_utils import RequestHandler
from ..utils.cli import print_status, progress_bar
from ..utils.validator import extract_params, parse_cookies, parse_post_data
from ..utils.logger import VulnerabilityLogger
from ..payloads.sql_payloads import ERROR_BASED, BOOLEAN_BASED, TIME_BASED, UNION_BASED, DB_FINGERPRINT, WAF_BYPASS
from ..techniques.error_based import ErrorBasedDetector
from ..techniques.boolean_based import BooleanBasedDetector
from ..techniques.time_based import TimeBasedDetector
from ..techniques.union_based import UnionBasedDetector
from ..techniques.extractor import DatabaseExtractor


class Scanner:
    """Main SQL injection scanning engine"""

    def __init__(self, url, params=None, data=None, cookies=None, threads=5,
                 timeout=10, proxy=None, level=1, dump=False, batch=False, logger=None):
        """
        Initialize the scanner

        Args:
            url (str): Target URL
            params (list, optional): List of parameters to scan
            data (str, optional): POST data string
            cookies (str, optional): HTTP cookie string
            threads (int): Number of threads to use
            timeout (float): Request timeout in seconds
            proxy (str, optional): Proxy URL
            level (int): Scan level (1-3)
            dump (bool): Whether to attempt database dumping
            batch (bool): Whether to use batch mode (no user input)
            logger (logging.Logger, optional): Logger instance
        """
        self.url = url
        self.params = params
        self.data_string = data
        self.cookie_string = cookies
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.level = level
        self.dump = dump
        self.batch = batch
        self.logger = logger

        # Parse data and cookies
        self.data = parse_post_data(data) if data else {}
        self.cookies = parse_cookies(cookies) if cookies else {}

        # Create request handler
        self.request_handler = RequestHandler(
            timeout=timeout,
            proxy=proxy,
            cookies=self.cookies
        )

        # Create vulnerability logger
        self.vuln_logger = VulnerabilityLogger()

        # Detect parameters if not provided
        if not self.params:
            self.params = list(extract_params(url).keys())

            # Add POST parameters if available
            if self.data:
                self.params.extend(list(self.data.keys()))

        # Prepare payloads based on scan level
        self.prepare_payloads()

        # Detected vulnerabilities
        self.vulnerabilities = []

    def prepare_payloads(self):
        """Prepare payloads based on scan level"""
        # Level 1: Basic payloads (about 25% of all payloads)
        # Level 2: Medium payloads (about 50% of all payloads)
        # Level 3: All payloads

        if self.level == 1:
            # Basic scan - fewer payloads
            self.error_payloads = ERROR_BASED[:7]
            self.boolean_payloads = BOOLEAN_BASED[:6]
            self.time_payloads = TIME_BASED[:4]
            self.union_payloads = []  # Skip UNION-based at level 1
        elif self.level == 2:
            # Medium scan
            self.error_payloads = ERROR_BASED[:15]
            self.boolean_payloads = BOOLEAN_BASED[:12]
            self.time_payloads = TIME_BASED[:10]
            # Skip UNION-based at level 2 (will run if others detect vulnerabilities)
            self.union_payloads = []
        else:
            # Level 3: Thorough scan - all payloads
            self.error_payloads = ERROR_BASED
            self.boolean_payloads = BOOLEAN_BASED
            self.time_payloads = TIME_BASED
            self.union_payloads = UNION_BASED  # Include UNION-based at level 3

    def scan_parameter(self, parameter):
        """
        Scan a single parameter for SQL injection

        Args:
            parameter (str): Parameter to scan

        Returns:
            dict: Scan results for this parameter
        """
        self.logger.info(f"Scanning parameter: {parameter}")

        # Determine if parameter is in URL or POST data
        is_post = parameter in self.data
        data = self.data if is_post else None

        # Results for this parameter
        results = {
            'parameter': parameter,
            'is_vulnerable': False,
            'techniques': [],
            'database_type': None
        }

        # 1. Check for Error-based SQL Injection
        self.logger.info(
            f"Testing Error-based SQL injection on parameter: {parameter}")
        error_detector = ErrorBasedDetector(
            self.url, self.request_handler, self.logger, self.vuln_logger)
        is_vuln_error, db_type_error, payload_error = error_detector.scan_parameter(
            parameter, self.error_payloads, is_post, data
        )

        if is_vuln_error:
            results['is_vulnerable'] = True
            results['techniques'].append('Error-based')
            results['database_type'] = db_type_error if db_type_error and db_type_error != 'general' else results['database_type']

        # 2. Check for Boolean-based SQL Injection
        self.logger.info(
            f"Testing Boolean-based SQL injection on parameter: {parameter}")
        boolean_detector = BooleanBasedDetector(
            self.url, self.request_handler, self.logger, self.vuln_logger)
        is_vuln_boolean, db_type_boolean, payload_boolean = boolean_detector.scan_parameter(
            parameter, self.boolean_payloads, is_post, data
        )

        if is_vuln_boolean:
            results['is_vulnerable'] = True
            results['techniques'].append('Boolean-based')
            results['database_type'] = db_type_boolean if db_type_boolean != 'Unknown' else results['database_type']

        # 3. Check for Time-based SQL Injection
        self.logger.info(
            f"Testing Time-based SQL injection on parameter: {parameter}")
        time_detector = TimeBasedDetector(
            self.url, self.request_handler, self.logger, self.vuln_logger)
        is_vuln_time, db_type_time, payload_time = time_detector.scan_parameter(
            parameter, self.time_payloads, is_post, data
        )

        if is_vuln_time:
            results['is_vulnerable'] = True
            results['techniques'].append('Time-based')
            results['database_type'] = db_type_time if db_type_time != 'Unknown' else results['database_type']

        # 4. Check for Union-based SQL Injection
        # Only run if other tests detected vulnerabilities or we're at level 3
        if results['is_vulnerable'] or self.level == 3:
            self.logger.info(
                f"Testing Union-based SQL injection on parameter: {parameter}")
            union_detector = UnionBasedDetector(
                self.url, self.request_handler, self.logger, self.vuln_logger)
            is_vuln_union, db_type_union, payload_union = union_detector.scan_parameter(
                parameter, is_post, data
            )

            if is_vuln_union:
                results['is_vulnerable'] = True
                results['techniques'].append('Union-based')
                results['database_type'] = db_type_union if db_type_union != 'Unknown' else results['database_type']

        # 5. Try to extract database information if parameter is vulnerable and dump is enabled
        if results['is_vulnerable'] and self.dump:
            self.logger.info(
                f"Attempting to extract database information from parameter: {parameter}")
            print_status(
                f"Attempting to extract database information from parameter: {parameter}", "info")

            extractor = DatabaseExtractor(
                self.url, parameter, results['database_type'],
                self.request_handler, self.logger, self.vuln_logger,
                is_post, data
            )

            extraction_results = extractor.extract_all()
            results['extraction'] = extraction_results

        # Store results
        if results['is_vulnerable']:
            self.vulnerabilities.append(results)

        return results

    def start(self):
        """Start scanning process"""
        self.logger.info(f"Starting scan with {self.threads} threads")
        print_status(f"Starting scan with {self.threads} threads", "info")

        start_time = time.time()

        # Check if we have parameters to scan
        if not self.params:
            self.logger.warning("No parameters found to scan")
            print_status(
                "No parameters found to scan. Please provide parameters with --params or use a URL with query parameters.", "warning")
            return

        # Display parameters to scan
        self.logger.info(f"Parameters to scan: {', '.join(self.params)}")
        print_status(f"Parameters to scan: {', '.join(self.params)}", "info")

        # Use ThreadPoolExecutor to scan parameters in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit tasks
            future_to_param = {executor.submit(
                self.scan_parameter, param): param for param in self.params}

            # Process results as they complete
            total_params = len(self.params)
            completed = 0

            for future in concurrent.futures.as_completed(future_to_param):
                param = future_to_param[future]
                try:
                    result = future.result()
                    completed += 1

                    # Update progress bar
                    progress_bar(completed, total_params,
                                 prefix=f'Progress:',
                                 suffix=f'Complete ({completed}/{total_params})',
                                 length=50)

                    # Report vulnerability if found
                    if result['is_vulnerable']:
                        print_status(
                            f"Parameter '{param}' is vulnerable to SQL injection", "vuln")
                        print_status(
                            f"Techniques: {', '.join(result['techniques'])}", "info")
                        print_status(
                            f"Database type: {result['database_type'] or 'Unknown'}", "info")
                except Exception as e:
                    self.logger.error(
                        f"Error scanning parameter {param}: {str(e)}")
                    print_status(
                        f"Error scanning parameter {param}: {str(e)}", "error")
                    completed += 1

                    # Update progress bar
                    progress_bar(completed, total_params,
                                 prefix=f'Progress:',
                                 suffix=f'Complete ({completed}/{total_params})',
                                 length=50)

        # Display results summary
        end_time = time.time()
        scan_duration = end_time - start_time

        print_status(f"Scan completed in {scan_duration:.2f} seconds", "info")
        print_status(f"Total parameters scanned: {len(self.params)}", "info")
        print_status(
            f"Vulnerable parameters found: {len(self.vulnerabilities)}", "info")

        # Export vulnerability results if found
        if self.vulnerabilities:
            # Create output directory if it doesn't exist
            os.makedirs("output", exist_ok=True)

            # Generate timestamp-based filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            json_file = f"output/blacksql_results_{timestamp}.json"
            csv_file = f"output/blacksql_results_{timestamp}.csv"

            # Export results
            self.vuln_logger.export_to_json(json_file)
            self.vuln_logger.export_to_csv(csv_file)

            print_status(f"Results exported to JSON: {json_file}", "success")
            print_status(f"Results exported to CSV: {csv_file}", "success")

        return self.vulnerabilities
