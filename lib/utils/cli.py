#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLI utilities for blackSQL
"""

import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class ColorPrint:
    """Class for printing colored text to terminal"""

    @staticmethod
    def red(text):
        """Print red text"""
        print(f"{Fore.RED}{text}{Style.RESET_ALL}")

    @staticmethod
    def green(text):
        """Print green text"""
        print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")

    @staticmethod
    def yellow(text):
        """Print yellow text"""
        print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")

    @staticmethod
    def blue(text):
        """Print blue text"""
        print(f"{Fore.BLUE}{text}{Style.RESET_ALL}")

    @staticmethod
    def magenta(text):
        """Print magenta text"""
        print(f"{Fore.MAGENTA}{text}{Style.RESET_ALL}")

    @staticmethod
    def cyan(text):
        """Print cyan text"""
        print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")

    @staticmethod
    def bold(text):
        """Print bold text"""
        print(f"{Style.BRIGHT}{text}{Style.RESET_ALL}")


def print_banner():
    """Print the blackSQL banner"""
    banner = f"""
{Fore.RED}█▄▄ █░░ ▄▀█ █▀▀ █▄▀   █▀ █▀█ █░░
{Fore.RED}█▄█ █▄▄ █▀█ █▄▄ █░█   ▄█ █▄█ █▄▄

{Fore.CYAN}[*] {Fore.WHITE}Advanced SQL Injection Scanner
{Fore.CYAN}[*] {Fore.WHITE}Author: Mr Sharafdin
{Fore.CYAN}[*] {Fore.WHITE}Version: 1.0.0
    """
    print(banner)


def print_status(message, status):
    """Print a status message with appropriate color"""
    if status == "success":
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
    elif status == "info":
        print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")
    elif status == "warning":
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    elif status == "error":
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
    elif status == "vuln":
        print(f"{Fore.RED}[VULNERABLE] {message}{Style.RESET_ALL}")
    else:
        print(f"[?] {message}")


def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Display a progress bar in the terminal"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()
