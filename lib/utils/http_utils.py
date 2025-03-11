#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP utilities for blackSQL
"""

import time
import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


class RequestHandler:
    """Class to handle HTTP requests"""

    def __init__(self, timeout=10, proxy=None, user_agent=None, cookies=None):
        """
        Initialize the request handler

        Args:
            timeout (int): Request timeout in seconds
            proxy (str, optional): Proxy URL
            user_agent (str, optional): User agent string
            cookies (dict, optional): HTTP cookies
        """
        self.timeout = timeout
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None

        # Set default user agent if none provided
        if not user_agent:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': user_agent})

        if cookies:
            self.session.cookies.update(cookies)

    def get(self, url, params=None, additional_headers=None):
        """
        Send GET request

        Args:
            url (str): URL to send request to
            params (dict, optional): URL parameters
            additional_headers (dict, optional): Additional HTTP headers

        Returns:
            requests.Response: Response object
        """
        headers = {}
        if additional_headers:
            headers.update(additional_headers)

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False,  # Disable SSL verification
                allow_redirects=True
            )
            return response
        except RequestException as e:
            raise e

    def post(self, url, data=None, json=None, additional_headers=None):
        """
        Send POST request

        Args:
            url (str): URL to send request to
            data (dict, optional): Form data
            json (dict, optional): JSON data
            additional_headers (dict, optional): Additional HTTP headers

        Returns:
            requests.Response: Response object
        """
        headers = {}
        if additional_headers:
            headers.update(additional_headers)

        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False,  # Disable SSL verification
                allow_redirects=True
            )
            return response
        except RequestException as e:
            raise e


def inject_payload_in_url(url, parameter, payload):
    """
    Inject a payload into a URL parameter

    Args:
        url (str): Original URL
        parameter (str): Parameter to inject into
        payload (str): Payload to inject

    Returns:
        str: URL with injected payload
    """
    parsed_url = urlparse(url)
    query_params = dict(parse_qsl(parsed_url.query))

    # Inject payload
    if parameter in query_params:
        query_params[parameter] = payload
    else:
        # If parameter doesn't exist, add it
        query_params[parameter] = payload

    # Rebuild URL
    new_query = urlencode(query_params)
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))

    return new_url


def measure_response_time(request_func, *args, **kwargs):
    """
    Measure the response time of a request

    Args:
        request_func: Function to send HTTP request
        *args: Arguments to pass to the request function
        **kwargs: Keyword arguments to pass to the request function

    Returns:
        tuple: (response, response_time)
    """
    start_time = time.time()
    response = request_func(*args, **kwargs)
    end_time = time.time()

    response_time = end_time - start_time

    return response, response_time
