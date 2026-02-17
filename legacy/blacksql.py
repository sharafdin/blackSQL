#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
blackSQL - Advanced SQL Injection Scanner
Author: Mr Sharafdin
License: MIT
"""

import argparse
import sys
import os
from datetime import datetime

from lib.core.engine import Scanner
from lib.utils.cli import ColorPrint, print_banner
from lib.utils.validator import validate_url
from lib.utils.logger import setup_logger


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="blackSQL - Advanced SQL Injection Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-u", "--url",
                        help="Target URL (e.g., http://example.com/page.php?id=1)")
    parser.add_argument("-p", "--params",
                        help="Specify parameters to scan (e.g., 'id,page')")
    parser.add_argument("--data",
                        help="POST data (e.g., 'id=1&page=2')")
    parser.add_argument("-c", "--cookies",
                        help="HTTP cookies (e.g., 'PHPSESSID=value; admin=0')")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Connection timeout in seconds (default: 10.0)")
    parser.add_argument("--proxy",
                        help="Use a proxy (e.g., 'http://127.0.0.1:8080')")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=1,
                        help="Scan level (1-3, higher = more tests)")
    parser.add_argument("--dump", action="store_true",
                        help="Attempt to dump database tables when vulnerable")
    parser.add_argument("--batch", action="store_true",
                        help="Never ask for user input, use the default behavior")
    parser.add_argument("-o", "--output",
                        help="Save scan results to a file (CSV/JSON)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    """Main function to run the SQL injection scanner."""
    print_banner()

    args = parse_arguments()

    if not args.url:
        ColorPrint.red("Error: Target URL is required")
        sys.exit(1)

    if not validate_url(args.url):
        ColorPrint.red(f"Error: Invalid URL format: {args.url}")
        sys.exit(1)

    # Setup logging
    logger = setup_logger(args.output)
    logger.info(f"Scan started against {args.url}")

    try:
        # Initialize scanner
        scanner = Scanner(
            url=args.url,
            params=args.params.split(',') if args.params else None,
            data=args.data,
            cookies=args.cookies,
            threads=args.threads,
            timeout=args.timeout,
            proxy=args.proxy,
            level=args.level,
            dump=args.dump,
            batch=args.batch,
            logger=logger
        )

        # Start scanning
        ColorPrint.blue(f"[*] Starting scan against: {args.url}")
        ColorPrint.blue(
            f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        ColorPrint.blue(f"[*] Using {args.threads} threads")

        scanner.start()

        ColorPrint.blue(
            f"[*] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    except KeyboardInterrupt:
        ColorPrint.yellow("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        ColorPrint.red(f"[!] An error occurred: {str(e)}")
        logger.error(f"Scan error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
