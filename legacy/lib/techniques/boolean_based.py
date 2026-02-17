#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Boolean-based SQL injection detection
"""

import re
import difflib
from ..utils.http_utils import inject_payload_in_url
from ..utils.cli import print_status


class BooleanBasedDetector:
    """Class to detect boolean-based SQL injections"""

    def __init__(self, url, request_handler, logger, vuln_logger=None, similarity_threshold=0.95):
        """
        Initialize boolean-based detector

        Args:
            url (str): Target URL
            request_handler (RequestHandler): HTTP request handler instance
            logger (logging.Logger): Logger instance
            vuln_logger (VulnerabilityLogger, optional): Vulnerability logger
            similarity_threshold (float): Threshold for similarity comparison
        """
        self.url = url
        self.request_handler = request_handler
        self.logger = logger
        self.vuln_logger = vuln_logger
        self.similarity_threshold = similarity_threshold

    def content_difference(self, response1, response2):
        """
        Calculate difference between two responses

        Args:
            response1 (str): First response content
            response2 (str): Second response content

        Returns:
            float: Similarity ratio between the two responses (0.0 to 1.0)
        """
        # Remove dynamic content that might change between requests
        # (e.g., timestamps, session tokens, CSRF tokens)
        def normalize_content(content):
            # Remove potential time-based dynamic content
            content = re.sub(r'\d{2}:\d{2}:\d{2}', '', content)
            content = re.sub(r'\d{2}/\d{2}/\d{4}', '', content)

            # Remove potential tokens and hashes
            content = re.sub(r'[a-fA-F0-9]{32}', '', content)  # MD5
            content = re.sub(r'[a-fA-F0-9]{40}', '', content)  # SHA-1
            content = re.sub(r'[a-fA-F0-9]{64}', '', content)  # SHA-256

            # Remove whitespace
            content = re.sub(r'\s+', ' ', content)

            return content

        # Normalize content
        normalized1 = normalize_content(response1)
        normalized2 = normalize_content(response2)

        # Calculate similarity ratio
        similarity = difflib.SequenceMatcher(
            None, normalized1, normalized2).ratio()

        return similarity

    def has_significant_difference(self, true_response, false_response):
        """
        Check if there's a significant difference between responses

        Args:
            true_response (requests.Response): Response for TRUE condition
            false_response (requests.Response): Response for FALSE condition

        Returns:
            bool: True if significant difference exists, False otherwise
        """
        # Check if status codes differ
        if true_response.status_code != false_response.status_code:
            return True

        # Check response size difference
        true_size = len(true_response.text)
        false_size = len(false_response.text)
        size_diff_ratio = min(true_size, false_size) / max(true_size,
                                                           false_size) if max(true_size, false_size) > 0 else 1.0

        # If sizes are very different (less than 70% similarity in size)
        if size_diff_ratio < 0.7:
            return True

        # Check content similarity
        similarity = self.content_difference(
            true_response.text, false_response.text)

        # If similarity is below threshold, there's a significant difference
        return similarity < self.similarity_threshold

    def scan_parameter(self, parameter, payload_pairs, is_post=False, data=None):
        """
        Scan a parameter for boolean-based SQL injection

        Args:
            parameter (str): Parameter name to test
            payload_pairs (list): List of boolean payload pairs [(true_payload, false_payload), ...]
            is_post (bool): Whether to test POST parameter
            data (dict, optional): POST data

        Returns:
            tuple: (bool, str) - (is_vulnerable, payload)
        """
        self.logger.info(
            f"Testing parameter '{parameter}' for boolean-based SQL injection")

        # Create pairs of TRUE/FALSE condition payloads
        # Each pair should give different responses if injection exists
        true_false_pairs = []

        # Create TRUE/FALSE pairs for testing
        for i in range(0, len(payload_pairs), 2):
            if i + 1 < len(payload_pairs):
                true_payload = payload_pairs[i]
                false_payload = payload_pairs[i + 1]
                true_false_pairs.append((true_payload, false_payload))

        # Test each TRUE/FALSE pair
        for true_payload, false_payload in true_false_pairs:
            try:
                # Test TRUE condition
                if is_post:
                    # Modify POST data
                    true_test_data = data.copy()
                    true_test_data[parameter] = true_payload

                    # Send POST request
                    true_response = self.request_handler.post(
                        self.url, data=true_test_data)
                else:
                    # Inject TRUE payload into URL parameter
                    true_test_url = inject_payload_in_url(
                        self.url, parameter, true_payload)

                    # Send GET request
                    true_response = self.request_handler.get(true_test_url)

                # Test FALSE condition
                if is_post:
                    # Modify POST data
                    false_test_data = data.copy()
                    false_test_data[parameter] = false_payload

                    # Send POST request
                    false_response = self.request_handler.post(
                        self.url, data=false_test_data)
                else:
                    # Inject FALSE payload into URL parameter
                    false_test_url = inject_payload_in_url(
                        self.url, parameter, false_payload)

                    # Send GET request
                    false_response = self.request_handler.get(false_test_url)

                # Check if there's a significant difference between responses
                if self.has_significant_difference(true_response, false_response):
                    # Log vulnerability
                    print_status(
                        f"Parameter '{parameter}' is vulnerable to boolean-based SQL injection", "vuln")
                    print_status(f"TRUE payload: {true_payload}", "info")
                    print_status(f"FALSE payload: {false_payload}", "info")

                    # Try to determine database type
                    db_type = "Unknown"
                    # Look for database-specific syntax in the payloads
                    if any(kw in true_payload.upper() for kw in ["MYSQL", "SLEEP", "INFORMATION_SCHEMA"]):
                        db_type = "MySQL"
                    elif any(kw in true_payload.upper() for kw in ["MSSQL", "WAITFOR", "SYSOBJECTS"]):
                        db_type = "MSSQL"
                    elif any(kw in true_payload.upper() for kw in ["PG_", "POSTGRES"]):
                        db_type = "PostgreSQL"
                    elif any(kw in true_payload.upper() for kw in ["ORA", "ROWNUM"]):
                        db_type = "Oracle"
                    elif any(kw in true_payload.upper() for kw in ["SQLITE"]):
                        db_type = "SQLite"

                    print_status(f"Database type: {db_type}", "info")

                    self.logger.warning(
                        f"Found boolean-based SQL injection in parameter '{parameter}'")
                    self.logger.info(f"TRUE payload: {true_payload}")
                    self.logger.info(f"FALSE payload: {false_payload}")

                    if self.vuln_logger:
                        self.vuln_logger.add_vulnerability(
                            url=self.url,
                            injection_type="Boolean-based",
                            parameter=parameter,
                            payload=f"TRUE: {true_payload}, FALSE: {false_payload}",
                            database_type=db_type,
                            details={
                                "true_payload": true_payload,
                                "false_payload": false_payload,
                                "response_difference": 1.0 - self.content_difference(true_response.text, false_response.text)
                            }
                        )

                    return True, db_type, true_payload

            except Exception as e:
                self.logger.error(
                    f"Error testing payloads {true_payload}/{false_payload}: {str(e)}")
                continue

        print_status(
            f"Parameter '{parameter}' is not vulnerable to boolean-based SQL injection", "info")
        self.logger.info(
            f"No boolean-based SQL injection found in parameter '{parameter}'")

        return False, None, None
