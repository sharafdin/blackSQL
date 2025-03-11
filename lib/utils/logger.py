#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logging utilities for blackSQL
"""

import os
import json
import csv
import logging
from datetime import datetime


def setup_logger(output_file=None):
    """
    Set up and configure logger

    Args:
        output_file (str, optional): Path to output file

    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)

    # Generate timestamped filename if none provided
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"logs/blacksql_{timestamp}.log"
    else:
        log_file = output_file

    # Configure logger
    logger = logging.getLogger('blacksql')
    logger.setLevel(logging.INFO)

    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)

    # Create console handler
    console_handler = logging.StreamHandler()
    # Only warnings and errors to console
    console_handler.setLevel(logging.WARNING)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


class VulnerabilityLogger:
    """
    Class to log and export vulnerability findings
    """

    def __init__(self, output_file=None):
        """
        Initialize the vulnerability logger

        Args:
            output_file (str, optional): Path to output file
        """
        self.vulnerabilities = []
        self.output_file = output_file

    def add_vulnerability(self, url, injection_type, parameter, payload, database_type=None, details=None):
        """
        Add a vulnerability finding

        Args:
            url (str): Target URL
            injection_type (str): Type of SQL injection
            parameter (str): Vulnerable parameter
            payload (str): Payload that triggered the vulnerability
            database_type (str, optional): Detected database type
            details (dict, optional): Additional vulnerability details
        """
        vuln = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'injection_type': injection_type,
            'parameter': parameter,
            'payload': payload,
            'database_type': database_type,
            'details': details or {}
        }

        self.vulnerabilities.append(vuln)

    def export_to_json(self, filename=None):
        """
        Export vulnerabilities to JSON file

        Args:
            filename (str, optional): Output filename
        """
        if not filename:
            if self.output_file:
                filename = self.output_file
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"logs/vulnerabilities_{timestamp}.json"

        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w') as f:
            json.dump({
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4)

        return filename

    def export_to_csv(self, filename=None):
        """
        Export vulnerabilities to CSV file

        Args:
            filename (str, optional): Output filename
        """
        if not filename:
            if self.output_file:
                filename = self.output_file
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"logs/vulnerabilities_{timestamp}.csv"

        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w', newline='') as f:
            fieldnames = ['timestamp', 'url', 'injection_type',
                          'parameter', 'payload', 'database_type']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            for vuln in self.vulnerabilities:
                # Extract only the fields in fieldnames
                row = {field: vuln.get(field, '') for field in fieldnames}
                writer.writerow(row)

        return filename
