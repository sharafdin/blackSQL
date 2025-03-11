#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Validators for blackSQL
"""

import re
import urllib.parse


def validate_url(url):
    """
    Validate if a URL is properly formatted

    Args:
        url (str): URL to validate

    Returns:
        bool: True if the URL is valid, False otherwise
    """
    # Basic URL regex pattern
    pattern = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        # domain
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ipv4
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return bool(pattern.match(url))


def extract_params(url):
    """
    Extract parameters from a URL

    Args:
        url (str): URL to extract parameters from

    Returns:
        dict: Dictionary of parameters and their values
    """
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # Convert lists to single values
    params = {k: v[0] for k, v in query_params.items()}

    return params


def parse_cookies(cookie_string):
    """
    Parse cookie string into a dictionary

    Args:
        cookie_string (str): Cookie string (e.g., 'name=value; name2=value2')

    Returns:
        dict: Dictionary of cookie names and values
    """
    if not cookie_string:
        return {}

    cookies = {}

    for cookie in cookie_string.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()

    return cookies


def parse_post_data(data_string):
    """
    Parse POST data string into a dictionary

    Args:
        data_string (str): POST data string (e.g., 'name=value&name2=value2')

    Returns:
        dict: Dictionary of parameter names and values
    """
    if not data_string:
        return {}

    return dict(urllib.parse.parse_qsl(data_string))
