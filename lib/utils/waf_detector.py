#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF detection module for blackSQL
"""

import re
from ..utils.cli import print_status


class WAFDetector:
    """Class to detect Web Application Firewalls"""

    # Common WAF signatures
    WAF_SIGNATURES = {
        'Cloudflare': [
            r'cloudflare',
            r'cloudflare-nginx',
            r'__cfduid',
            r'cf-ray',
            r'CF-WAF'
        ],
        'AWS WAF': [
            r'aws-waf',
            r'awselb/2.0',
            r'x-amzn-waf',
            r'x-amz-cf-id'
        ],
        'ModSecurity': [
            r'mod_security',
            r'modsecurity',
            r'NOYB'
        ],
        'Akamai': [
            r'akamai',
            r'akamaighost',
            r'ak.v'
        ],
        'Imperva/Incapsula': [
            r'incapsula',
            r'imperva',
            r'incap_ses',
            r'visid_incap'
        ],
        'F5 BIG-IP': [
            r'BigIP',
            r'F5',
            r'BIGipServer',
            r'TS[0-9a-f]{24}='
        ],
        'Sucuri': [
            r'sucuri',
            r'cloudproxy',
            r'sucuri/cloudproxy'
        ],
        'Barracuda': [
            r'barracuda',
            r'barracuda_'
        ],
        'Fortinet/FortiWeb': [
            r'fortigate',
            r'fortiweb',
            r'fortinet'
        ],
        'Citrix NetScaler': [
            r'netscaler',
            r'ns_af=',
            r'citrix_ns'
        ]
    }

    # Common WAF block messages
    BLOCK_PATTERNS = [
        r'blocked',
        r'blocked by firewall',
        r'security policy',
        r'access denied',
        r'forbidden',
        r'illegal',
        r'unauthorized',
        r'suspicious activity',
        r'detected an attack',
        r'security rule',
        r'malicious',
        r'security violation',
        r'attack detected',
        r'automated request',
        r'your request has been blocked',
        r'your IP has been blocked',
        r'security challenge',
        r'challenge required',
        r'captcha',
        r'protection system'
    ]

    @staticmethod
    def detect(response):
        """
        Detect WAF from HTTP response

        Args:
            response (requests.Response): HTTP response object

        Returns:
            tuple: (is_waf_detected, waf_name) - (bool, str)
        """
        headers = response.headers
        content = response.text.lower()
        status_code = response.status_code

        # Check for WAF blocking response codes
        if status_code in [403, 406, 429, 503]:
            # Look for block messages in content
            for pattern in WAFDetector.BLOCK_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    # Blocked by some kind of WAF
                    return True, "Generic WAF"

        # Check for WAF signatures in headers and cookies
        for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
            for pattern in signatures:
                # Check in headers
                for header, value in headers.items():
                    if re.search(pattern, header + ": " + value, re.IGNORECASE):
                        return True, waf_name

                # Check in content
                if re.search(pattern, content, re.IGNORECASE):
                    return True, waf_name

        return False, None

    @staticmethod
    def check_target(request_handler, url, logger=None):
        """
        Check if target has WAF protection

        Args:
            request_handler (RequestHandler): HTTP request handler
            url (str): Target URL
            logger (logging.Logger, optional): Logger instance

        Returns:
            tuple: (is_waf_detected, waf_name) - (bool, str)
        """
        try:
            # First, make a normal request to the target
            response = request_handler.get(url)
            is_waf, waf_name = WAFDetector.detect(response)

            if is_waf:
                if logger:
                    logger.warning(f"WAF detected: {waf_name}")
                print_status(f"WAF detected: {waf_name}", "warning")
                print_status("WAF bypassing techniques will be used", "info")
                return True, waf_name

            # If not detected, try with a suspicious parameter
            test_url = url
            if "?" in url:
                test_url += "&sql=1%27%20OR%20%271%27%3D%271"
            else:
                test_url += "?sql=1%27%20OR%20%271%27%3D%271"

            response = request_handler.get(test_url)
            is_waf, waf_name = WAFDetector.detect(response)

            if is_waf:
                if logger:
                    logger.warning(
                        f"WAF detected on suspicious request: {waf_name}")
                print_status(
                    f"WAF detected when sending suspicious request: {waf_name}", "warning")
                print_status("WAF bypassing techniques will be used", "info")
                return True, waf_name

            if logger:
                logger.info("No WAF detected on target")
            print_status("No WAF detected on target", "info")
            return False, None

        except Exception as e:
            if logger:
                logger.error(f"Error checking for WAF: {str(e)}")
            print_status(f"Error checking for WAF: {str(e)}", "error")
            return False, None
