#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Time-based SQL injection detection
"""

import time
import statistics
from ..utils.http_utils import inject_payload_in_url, measure_response_time
from ..utils.cli import print_status


class TimeBasedDetector:
    """Class to detect time-based SQL injections"""

    def __init__(self, url, request_handler, logger, vuln_logger=None, delay_threshold=5):
        """
        Initialize time-based detector

        Args:
            url (str): Target URL
            request_handler (RequestHandler): HTTP request handler instance
            logger (logging.Logger): Logger instance
            vuln_logger (VulnerabilityLogger, optional): Vulnerability logger
            delay_threshold (int): Minimum delay threshold in seconds
        """
        self.url = url
        self.request_handler = request_handler
        self.logger = logger
        self.vuln_logger = vuln_logger
        self.delay_threshold = delay_threshold

    def calculate_baseline_times(self, is_post=False, data=None, num_samples=3):
        """
        Calculate baseline response times

        Args:
            is_post (bool): Whether using POST request
            data (dict, optional): POST data
            num_samples (int): Number of samples to collect

        Returns:
            float: Average baseline response time
        """
        baseline_times = []

        for _ in range(num_samples):
            try:
                if is_post:
                    response, response_time = measure_response_time(
                        self.request_handler.post, self.url, data=data
                    )
                else:
                    response, response_time = measure_response_time(
                        self.request_handler.get, self.url
                    )

                baseline_times.append(response_time)
                time.sleep(0.5)  # Small delay between samples
            except Exception as e:
                self.logger.error(f"Error measuring baseline time: {str(e)}")

        # Calculate average and standard deviation
        if baseline_times:
            avg_time = statistics.mean(baseline_times)
            self.logger.info(f"Baseline response time: {avg_time:.3f} seconds")
            return avg_time
        else:
            # Default in case of no successful measurements
            self.logger.warning(
                "Could not measure baseline times, using default")
            return 1.0

    def is_time_delayed(self, response_time, baseline_time):
        """
        Check if response time is significantly delayed

        Args:
            response_time (float): Response time to check
            baseline_time (float): Baseline response time

        Returns:
            bool: True if significantly delayed, False otherwise
        """
        # Check if the response time is significantly higher than baseline
        return response_time >= (baseline_time + self.delay_threshold * 0.8)

    def scan_parameter(self, parameter, payloads, is_post=False, data=None):
        """
        Scan a parameter for time-based SQL injection

        Args:
            parameter (str): Parameter name to test
            payloads (list): List of payloads to test
            is_post (bool): Whether to test POST parameter
            data (dict, optional): POST data

        Returns:
            tuple: (bool, str) - (is_vulnerable, payload)
        """
        self.logger.info(
            f"Testing parameter '{parameter}' for time-based SQL injection")

        # Calculate baseline response times
        baseline_time = self.calculate_baseline_times(is_post, data)

        # Check for time delays in each payload
        for payload in payloads:
            try:
                if is_post:
                    # Modify POST data
                    test_data = data.copy()
                    test_data[parameter] = payload

                    # Send POST request and measure time
                    response, response_time = measure_response_time(
                        self.request_handler.post, self.url, data=test_data
                    )
                else:
                    # Inject payload into URL parameter
                    test_url = inject_payload_in_url(
                        self.url, parameter, payload)

                    # Send GET request and measure time
                    response, response_time = measure_response_time(
                        self.request_handler.get, test_url
                    )

                # Check if response time is significantly delayed
                if self.is_time_delayed(response_time, baseline_time):
                    # Verify with a second request to confirm it's not a false positive
                    if is_post:
                        verify_response, verify_time = measure_response_time(
                            self.request_handler.post, self.url, data=test_data
                        )
                    else:
                        verify_response, verify_time = measure_response_time(
                            self.request_handler.get, test_url
                        )

                    if self.is_time_delayed(verify_time, baseline_time):
                        # Determine database type based on the payload
                        db_type = "Unknown"
                        if "SLEEP" in payload.upper():
                            db_type = "MySQL"
                        elif "PG_SLEEP" in payload.upper():
                            db_type = "PostgreSQL"
                        elif "WAITFOR DELAY" in payload.upper():
                            db_type = "MSSQL"

                        # Log vulnerability
                        print_status(
                            f"Parameter '{parameter}' is vulnerable to time-based SQL injection", "vuln")
                        print_status(f"Database type: {db_type}", "info")
                        print_status(f"Payload: {payload}", "info")
                        print_status(
                            f"Response time: {response_time:.3f}s (baseline: {baseline_time:.3f}s)", "info")

                        self.logger.warning(
                            f"Found time-based SQL injection in parameter '{parameter}' with payload: {payload}")
                        self.logger.info(
                            f"Response time: {response_time:.3f}s, baseline: {baseline_time:.3f}s")

                        if self.vuln_logger:
                            self.vuln_logger.add_vulnerability(
                                url=self.url,
                                injection_type="Time-based",
                                parameter=parameter,
                                payload=payload,
                                database_type=db_type,
                                details={"response_time": response_time,
                                         "baseline_time": baseline_time}
                            )

                        return True, db_type, payload

            except Exception as e:
                self.logger.error(f"Error testing payload {payload}: {str(e)}")
                continue

        print_status(
            f"Parameter '{parameter}' is not vulnerable to time-based SQL injection", "info")
        self.logger.info(
            f"No time-based SQL injection found in parameter '{parameter}'")

        return False, None, None
