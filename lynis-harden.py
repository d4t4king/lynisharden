#!/usr/bin/env python3

import os
import apt
import ast
import sys
import argparse
import pprint
import subprocess
from termcolor import cprint
from typing import Literal,Any

LYNIS_CUSTOM_PROFILE='/etc/lynis/custom.prf'
LYNIS_REPORT_PATH='/var/log/lynis-report.dat'
LYNIS_LOG_PATH='/var/log/lynis.log'

def _verbose_print(enabled: bool, message: str) -> None:
    if enabled:
        print(f"{message}")

def _warn_print(enabled: bool, message: str) -> None:
    if enabled:
        cprint(f"WARNING: {message}", "yellow")

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("""
        Harden your linux for lynis.
    """)
    verbose_quiet_debug = parser.add_mutually_exclusive_group()
    verbose_quiet_debug.add_argument('-v', '--verbose', action='store_true', help="Adds more output.  Usually for troubleshooting.")
    verbose_quiet_debug.add_argument('-q', '--quiet', help="Suppress all output except errors.")
    verbose_quiet_debug.add_argument('-D', '--debug', help="All the outputs.")
    return parser.parse_args()

def parse_value(_value: str) -> Any:
    """ Converts string values into native python data types. """
    value_lower = _value.lower()
    if value_lower == "true":
        return True
    if value_lower == "false":
        return False
    if value_lower in ("none", "null", ""):
        return None

    try:
        # Converts digits to ints, decimals to floats, and structures to lists/dicts
        return ast.literal_eval(_value)
    except (ValueError, SyntaxError):
        # Fallback to the raw string if literal_eval fails
        return _value

def read_lynis_report(report_path: str) -> dict:
    lynis_report = {}
    if not os.path.exists(LYNIS_REPORT_PATH):
        raise FileNotFoundError
    with open(LYNIS_REPORT_PATH, 'r') as lynis_report_file:
        for line in lynis_report_file:
            line = line.strip()
            if '=' in line:
                key, raw_value = line.split('=', 1)
                key = key.strip()

                # convert the value type
                cleaned_value = parse_value(raw_value.strip())

    return lynis_report

def is_apt_package_installed(package_name: str) -> bool:
    try:
        cache = apt.Cache()
        if package_name in cache:
            return cache[package_name].is_installed
        return False
    except ImportError:
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Status}", package_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return "install ok installed" in result.stdout
        except FileNotFoundError:
            cprint("ERROR: This system does not support dpkg/apt packages.", "red")
            return False

def install_apt_package(enabled: bool, package_name: str) -> bool:
    cache = apt.Cache()

    try:
        cache.update()
        cache.open()

        if package_name in cache:
            package = cache[package_name]

            if package.is_installed:
                _verbose_print(True, f"Package '{package_name}' is already installed.")
                return True

            package.mark_install()

            _verbose_print(enabled, f"Comitting changes to install {package_name}...")
            cache.commit()
            _verbose_print(enabled, f"Successfully installed {package_name}")
            return True
        else:
            cprint(f"WARNING: Package '{package_name}' not found in the APT repository.", "yellow", file=sys.stderr)
            return False
    except Exception as _error:
        cprint(f"ERROR: Installation failed: {_error}", "red", file=sys.stderr)
        return False

def main():
    __uid = os.getuid()
    __euid = os.geteuid()

    if not __uid == 0 and not __euid == 0:
        _warn_print(True, f"You should run this as root.")
        return sys.exit(1)
    
    arguments = parse_arguments()
    if arguments.debug:
        arguments.verbose = True

    if not os.path.exists(LYNIS_CUSTOM_PROFILE):
        _warn_print(arguments.verbose, f"The lynis custom profile path does not exist or is not complete.  Check {LYNIS_CUSTOM_PROFILE}.")
    else:
        _verbose_print(arguments.verbose, f"{LYNIS_CUSTOM_PROFILE} already exists.")

    # These checks (and corrections) are in no particular order.  They were written
    # in the order in which they were experienced on my test systems.

    package_installs_status = {}
    if not is_apt_package_installed("ufw"):
        package_installs_status["ufw"] = install_apt_package(arguments.verbose, "ufw")


if __name__=='__main__':
    raise SystemExit(main())