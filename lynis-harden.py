#!/usr/bin/env python3

import os
import re
# import apt
import ast
# import dnf
import sys
import json
import socket
import pprint
import argparse
import datetime
import tempfile
import subprocess
from termcolor import cprint
from typing import Literal,Any
from dataclasses import dataclass
from zoneinfo import ZoneInfo
from pathlib import Path

#region CONSTANTS
LYNIS_CUSTOM_PROFILE = Path('/etc/lynis/custom.prf')
LYNIS_REPORT_PATH = Path('/var/log/lynis-report.dat')
LYNIS_LOG_PATH = Path('/var/log/lynis.log')
DEBIAN_LIKE = ["debian", "ubuntu", "linuxmint", "pop", "kali", "parrot"]
RHEL_LIKE = ["rhel", "centos", "fedora", "almalinux", "rocky", "oracle"]
COMPILER_PATHS = ["/usr/bin/c98-gcc", "/usr/bin/c99-gcc", "/usr/bin/gcc-11", \
    "/usr/bin/clang", "/usr/bin/cc", "/usr/bin/c++", "/usr/bin/g++", "/usr/bin/as", \
    "/usr/bin/x86_64-linux-gnu-gcc", "/usr/bin/x86_64-linux-gnu-g++", "/usr/bin/x86_64-linux-gnu-as", \
    "/usr/bin/x86_64-linux-gnu-gcc-10", "/usr/bin/x86_64-linux-gnu-gcc-11", "/usr/bin/x86_64-linux-gnu-gcc-12", \
    "/usr/bin/x86_64-linux-gnu-gcc-13", "/usr/bin/x86_64-linux-gnu-gcc-14", "/usr/bin/x86_64-linux-gnu-gcc-ar-10", \
    "/usr/bin/x86_64-linux-gnu-gcc-ar-11", "/usr/bin/x86_64-linux-gnu-gcc-ar-12", \
    "/usr/bin/x86_64-linux-gnu-gcc-ar-13", "/usr/bin/x86_64-linux-gnu-gcc-nm-10", \
    "/usr/bin/x86_64-linux-gnu-gcc-nm-11", "/usr/bin/x86_64-linux-gnu-gcc-nm-12", \
    "/usr/bin/x86_64-linux-gnu-gcc-nm-13", "/usr/bin/x86_64-linux-gnu-gcc-ranlib-10", \
    "/usr/bin/x86_64-linux-gnu-gcc-ranlib-11", "/usr/bin/x86_64-linux-gnu-gcc-ranlib-12", \
    "/usr/bin/x86_64-linux-gnu-gcc-ranlib-13", "/usr/bin/x86_64-linux-gnu-gcov-10", "/usr/bin/x86_64-linux-gnu-gcov-11", \
    "/usr/bin/x86_64-linux-gnu-gcov-12", "/usr/bin/x86_64-linux-gnu-gcov-13", "/usr/bin/x86_64-linux-gnu-gcov-dump-10", \
    "/usr/bin/x86_64-linux-gnu-gcov-dump-11", "/usr/bin/x86_64-linux-gnu-gcov-dump-12", \
    "/usr/bin/x86_64-linux-gnu-gcov-dump-13", "/usr/bin/x86_64-linux-gnu-gcov-tool-10", \
    "/usr/bin/x86_64-linux-gnu-gcov-tool-11", "/usr/bin/x86_64-linux-gnu-gcov-tool-12", \
    "/usr/bin/x86_64-linux-gnu-gcov-tool-13", "/usr/bin/x86_64-linux-gnu-gcc-as"]
HARDENING_DATA_FILE = "./hardening.conf"
#endregion

#region DataClasses

@dataclass
class AssessmentDetail:
    test_id: str
    object_id: str
    description: str
    field: str
    preferred_value: str | int | bool | None
    actual_value: str | int | bool | None

@dataclass
class JournalMetaData:
    file_path: str
    file_id: str
    machine_id: str
    boot_id: str
    sequential_number_id: str
    state: str
    compatible_flags: list[str]
    incompatible_flags: list[str]
    header_size: int
    arena_size: int
    data_hashtable_size: int
    field_hashtable_size: int
    rotate_suggested: bool
    head_sequential_number: str
    tail_sequential_number: str
    head_realtime_timestamp: str
    tail_realtime_timestamp: str
    tail_monotonic_timestamp: str
    objects: int
    entry_object: int
    data_objects: int
    data_hashtable_fill: str
    field_objects: int
    field_hashtable_fill: str
    tag_objects: int
    entry_array_objects: int
    deepest_field_hash_chain: int
    deepest_data_hash_chain: int
    disk_usage: str

@dataclass
class NetworkListener:
    flags: list[str]
    protocol: str
    address: str
    port: int
    service: str

@dataclass
class Suggestion:
    test_id: str
    description: str
    solution: str
    skip_test: str

@dataclass
class Warning:
    test_id: str
    description: str
    solution: str
    skip_test: str

@dataclass
class DeletedFile:
    file_path: str
    flags: str
    _type: int
    size: str

#endregion

#region Script Utility Functions

def _verbose_pretty_print(enabled: bool, _object: object, _indent: int =4) -> None:
    pretty_printer = pprint.PrettyPrinter(indent=_indent)
    if enabled:
        pretty_printer.pprint(_object)

def _verbose_print(enabled: bool, message: str) -> None:
    if enabled:
        print(f"{message}")

def _warn_print(enabled: bool, message: str) -> None:
    if enabled:
        cprint(f"WARNING: {message}", "yellow")

def _dryrun_print(message: str, *args, **kwargs) -> None:
    cprint(f"DRY RUN: {message}", "cyan", kwargs)

def _get_local_ip(verbose: bool =False) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not need to be reachable
        sock.connect(('8.8.8.8', 1))
        local_ip = sock.getsockname()[0]
    except Exception as e:
        _warn_print(verbose, f"Error occurred while fetching local IP: {e}")
        local_ip = "127.0.0.1"
    finally:
        sock.close()
    return local_ip

def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("""
        Harden your linux for lynis.
    """)
    verbose_quiet_debug = parser.add_mutually_exclusive_group()
    verbose_quiet_debug.add_argument('-v', '--verbose', action='store_true', help="Adds more output.  Usually for troubleshooting.")
    verbose_quiet_debug.add_argument('-q', '--quiet', action='store_true', help="Suppress all output except errors.")
    verbose_quiet_debug.add_argument('-D', '--debug', action='store_true', help="All the outputs.")
    parser.add_argument('--yes', dest='yes_all', action='store_true', help="Assume yes to all prompts and run non-interactively.")
    parser.add_argument('--dry-run', action='store_true', help="Perform a dry run without making any changes.")
    parser.add_argument('--alt-lynis-report', help="Parse an alternate lynis-report.dat")
    return parser.parse_args()

def _append_file(file_path: str, content: str, verbose: bool =False) -> None:
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(content)
        _verbose_print(verbose, f"Appended content to {file_path}.")
    except FileNotFoundError:
        cprint(f"ERROR: File {file_path} not found.", "red", file=sys.stderr)
    except Exception as e:
        cprint(f"ERROR: Failed to append to {file_path}: {e}", "red", file=sys.stderr)

#endregion

#region Script Support/Discovery Functions

def parse_value(_value: str, key: str = "") -> Any:
    """Convert a raw report value to the most natural Python type."""
    value = _value.strip()
    if not value:
        return None

    value_lower = value.lower()
    if value_lower == "true":
        return True
    if value_lower == "false":
        return False
    if value_lower in ("none", "null"):
        return None

    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        pass

    if key in {"binaries_sgid_count", "binaries_suid_count"}:
        # Example: binaries_suid_count=/usr/bin/chfn /usr/bin/sudo
        return [part for part in value.split() if part]

    if key == "installed_packages_array":
        # Example: installed_packages_array=7zip,25.01+dfsg-1~deb13u2|aardvark-dns,1.14.0-3
        items = []
        for entry in value.split("|"):
            entry = entry.strip()
            if not entry or "," not in entry:
                continue
            package_name, package_version = entry.split(",", 1)
            items.append({package_name.strip(): package_version.strip()})
        return items

    if key == "open_empty_log_file[]":
        # Example: open_empty_log_file[]=MainThrea,/home/user/.log
        return [value]

    if key == "real_user[]":
        # Example: real_user[]=root,0|charlie,1000
        return [
            {user.split(",", 1)[0].strip(): int(user.split(",", 1)[1].strip())}
            for user in value.split("|")
            if user.strip()
        ]

    if key == "slow_test[]":
        # Example: slow_test[]=PLGN-0010,14.106227|PLGN-3812,43.353118
        items = []
        for entry in value.split("|"):
            entry = entry.strip()
            if not entry:
                continue
            test_id, duration = entry.split(",", 1)
            items.append({test_id.strip(): float(duration.strip())})
        return items

    if key == "systemd_unit_file[]":
        # Example: systemd_unit_file[]=proc-sys-fs-binfmt_misc.automount|static|
        parts = [part.strip() for part in value.split("|") if part.strip()]
        if len(parts) >= 2:
            unit_name, unit_state = parts[0], parts[1]
            return [{unit_name: unit_state}]
        return []

    if key == "cronjob[]":
        # Example: cronjob[]=17,*,*,*,*,root,cd,/,&&,run-parts,--report,/etc/cron.hourly
        return [entry.strip() for entry in value.split("|") if entry.strip()]

    if key == "deleted_file[]":
        # Example: deleted_file[]=/memfd:pipewire-memfd:flags=0x0000000f,type=2,size=2312(pipewire)
        items = []
        for entry in value.split("|"):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split("(", 1)
            if len(parts) != 2:
                continue
            path, suffix = parts
            path = path.rstrip()
            metadata = suffix.rstrip(")")
            flags = ""
            file_type = None
            size = None
            for token in metadata.split(","):
                if token.startswith("flags="):
                    flags = token.split("=", 1)[1]
                elif token.startswith("type="):
                    file_type = int(token.split("=", 1)[1])
                elif token.startswith("size="):
                    size = token.split("=", 1)[1]
            items.append(DeletedFile(file_path=path, flags=flags, _type=file_type or 0, size=size or ""))
        return items

    if key == "details[]":
        # Example: details[]=SSH-7408|sshd|desc:sshd option AllowTcpForwarding;field:AllowTcpForwarding;prefval:NO;value:YES;|
        items = []
        parts = [part.strip() for part in value.split("|") if part.strip()]
        if len(parts) >= 3:
            test_id = parts[0]
            object_id = parts[1]
            payload = parts[2]
            item = {
                "test_id": test_id,
                "object_id": object_id,
                "description": "",
                "field": "",
                "preferred_value": None,
                "actual_value": None,
            }
            for field in payload.split(";"):
                if not field or ":" not in field:
                    continue
                key_name, field_value = field.split(":", 1)
                if key_name == "desc":
                    item["description"] = field_value
                elif key_name == "field":
                    item["field"] = field_value
                elif key_name == "prefval":
                    item["preferred_value"] = parse_value(field_value)
                elif key_name == "value":
                    item["actual_value"] = parse_value(field_value)
            items.append(AssessmentDetail(**item))
        return items

    if key == "journal_meta_data":
        # Example: journal_meta_data=Filepath:/var/log/journal/... ,FileID:...,MachineID:...,BootID:...,|,
        records = []
        for raw_record in value.split("|,"):
            record = raw_record.strip()
            if not record:
                continue
            payload = {}
            for field in record.split(","):
                field = field.strip()
                if not field or ":" not in field:
                    continue
                field_name, field_value = field.split(":", 1)
                payload[field_name.strip()] = field_value.strip()
            if payload:
                def _coerce_int(value: str) -> int:
                    return int(value.replace("", "") or 0) if value else 0

                records.append(JournalMetaData(
                    file_path=payload.get("Filepath", ""),
                    file_id=payload.get("FileID", ""),
                    machine_id=payload.get("MachineID", ""),
                    boot_id=payload.get("BootID", ""),
                    sequential_number_id=payload.get("SequentialnumberID", ""),
                    state=payload.get("State", ""),
                    compatible_flags=[flag.strip() for flag in payload.get("Compatibleflags", "").split() if flag.strip()],
                    incompatible_flags=[flag.strip() for flag in payload.get("Incompatibleflags", "").split() if flag.strip()],
                    header_size=_coerce_int(payload.get("Headersize", "")),
                    arena_size=_coerce_int(payload.get("Arenasize", "")),
                    data_hashtable_size=_coerce_int(payload.get("Datahashtablesize", "")),
                    field_hashtable_size=_coerce_int(payload.get("Fieldhashtablesize", "")),
                    rotate_suggested=str(payload.get("Rotatesuggested", "")).lower() == "yes",
                    head_sequential_number=payload.get("Headsequentialnumber", ""),
                    tail_sequential_number=payload.get("Tailsequentialnumber", ""),
                    head_realtime_timestamp=payload.get("Headrealtimetimestamp", ""),
                    tail_realtime_timestamp=payload.get("Tailrealtimetimestamp", ""),
                    tail_monotonic_timestamp=payload.get("Tailmonotonictimestamp", ""),
                    objects=_coerce_int(payload.get("Objects", "")),
                    entry_object=_coerce_int(payload.get("Entryobjects", "")),
                    data_objects=_coerce_int(payload.get("Dataobjects", "")),
                    data_hashtable_fill=payload.get("Datahashtablefill", ""),
                    field_objects=_coerce_int(payload.get("Fieldobjects", "")),
                    field_hashtable_fill=payload.get("Fieldhashtablefill", ""),
                    tag_objects=_coerce_int(payload.get("Tagobjects", "")),
                    entry_array_objects=_coerce_int(payload.get("Entryarrayobjects", "")),
                    deepest_field_hash_chain=_coerce_int(payload.get("Deepestfieldhashchain", "")),
                    deepest_data_hash_chain=_coerce_int(payload.get("Deepestdatahashchain", "")),
                    disk_usage=payload.get("Diskusage", ""),
                ))
        return records

    if key == "network_listen[]":
        # Example: network_listen[]=raw,ss,v1|udp|0.0.0.0:53|pihole-FTL|
        parts = [part.strip() for part in value.split("|") if part.strip()]
        if len(parts) >= 4:
            flags = parts[0].split(",") if "," in parts[0] else [parts[0]]
            protocol = parts[1]
            address = parts[2]
            port = int(address.rsplit(":", 1)[-1]) if ":" in address else 0
            service = parts[3]
            return [NetworkListener(flags=flags, protocol=protocol, address=address, port=port, service=service)]
        return []

    if key == "suggestion[]":
        # Example: suggestion[]=BOOT-5264|Consider hardening system services|Run '/usr/bin/systemd-analyze security SERVICE' for each service|-|
        parts = [part.strip() for part in value.split("|") if part.strip()]
        if len(parts) >= 4:
            test_id, description, solution, skip_test = parts[:4]
            return [Suggestion(test_id=test_id, description=description, solution=solution, skip_test=skip_test)]
        return []

    if key == "warning[]":
        # Example: warning[]=PKGS-7392|Found one or more vulnerable packages.|-|-|
        parts = [part.strip() for part in value.split("|") if part.strip()]
        if len(parts) >= 4:
            test_id, description, solution, skip_test = parts[:4]
            return [Warning(test_id=test_id, description=description, solution=solution, skip_test=skip_test)]
        return []

    if "|" in value:
        parts = [part.strip() for part in value.split("|") if part.strip()]
        if parts and all("=" in part for part in parts):
            return [
                {
                    item_key.strip(): parse_value(item_value.strip(), item_key.strip())
                    for item_key, item_value in (
                        entry.split("=", 1) for entry in part.split(",")
                    )
                }
                for part in parts
            ]
        return [parse_value(part, key) for part in parts]

    if "," in value:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if len(parts) > 1:
            return [parse_value(part, key) for part in parts]

    return value

def read_lynis_report(report_path: str =LYNIS_REPORT_PATH, verbose: bool =False) -> dict:
    _lynis_report = {}
    if not os.path.exists(report_path):
        raise FileNotFoundError(report_path)

    with open(report_path, 'r', encoding='utf-8') as lynis_report_file:
        for line in lynis_report_file:
            line = line.strip()
            if '=' in line:
                key, raw_value = line.split('=', 1)
                key = key.strip()
                cleaned_value = parse_value(raw_value.strip(), key)

                if key in _lynis_report:
                    if isinstance(cleaned_value, list) and not _lynis_report[key]:
                        _lynis_report[key] = cleaned_value
                    elif isinstance(cleaned_value, list):
                        _lynis_report[key].extend(cleaned_value)
                    elif isinstance(_lynis_report[key], list):
                        _lynis_report[key].append(cleaned_value)
                    else:
                        _lynis_report[key] = [_lynis_report[key], cleaned_value]
                else:
                    _lynis_report[key] = cleaned_value

    return _lynis_report

# This function needs some tweaking.  It works OK for non-apt/dnf modules, but things get wonky with 
# circular references, etc.  Also, in order for it to work, you have to return the imported/installed
# module name to a varaible of that name, so it exists in the script's namespace.
def import_or_install(package_name: str, verbose: bool =False) -> Any:
    try:
        return __import__(package_name)
    except ImportError:
        _warn_print(verbose, f"Package '{package_name}' is not installed. Attempting to install...")
        if get_distro(verbose) in DEBIAN_LIKE:
            if install_apt_package(verbose, package_name):
                _verbose_print(verbose, f"Successfully installed '{package_name}'.")
                return __import__(package_name)
            else:
                cprint(f"ERROR: Failed to install '{package_name}'. Please install it manually.", "red", file=sys.stderr)
                sys.exit(1)
        elif get_distro(verbose) in RHEL_LIKE:
            if install_dnf_package(verbose, package_name):
                _verbose_print(verbose, f"Successfully installed '{package_name}'.")
                return __import__(package_name)
            else:
                cprint(f"ERROR: Failed to install '{package_name}'.  Please install it manually.", "red", file=sys.stderr)
                sys.exit(1)
        else:
            cprint(f"ERROR: Automatic installation of '{package_name}' is not supported on this distribution. Please install it manually.", "red", file=sys.stderr)
            sys.exit(1)

def is_apt_package_installed(package_name: str, verbose: bool =False) -> bool:
    # TODO: Change to use subprocess to be more platform/distro agnostic.
    # _import_or_install("apt", verbose)
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

def is_dnf_package_installed(package_name: str, verbose: bool =False) -> bool:
    _import_or_install("dnf", verbose)
    try:
        base = dnf.Base()
        base.fill_sack(load_system_repo=True, load_available_repos=False)

        # Filter the installed packaged (@system) by name
        installed_packages = base.sack.query().installed().filter(name=package_name) # type: ignore
        return bool(installed_packages)

    except Exception as e:
        cprint(f"ERROR: Failed to check DNF package installation: {e}", "red", file=sys.stderr)
        return False

def load_etc_passwd(verbose: bool =False) -> dict[str, dict[str, str]]:
    passwd_data = {}
    try:
        with open('/etc/passwd', 'r', encoding='utf-8') as passwd_file:
            for line in passwd_file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                if len(parts) >= 7:
                    username, password, uid, gid, gecos, home_dir, shell = parts[:7]
                    passwd_data[username] = {
                        'password': password,
                        'uid': int(uid),
                        'gid': int(gid),
                        'gecos': gecos,
                        'home_dir': home_dir,
                        'shell': shell
                    }
    except FileNotFoundError:
        cprint("ERROR: /etc/passwd file not found.", "red", file=sys.stderr)
    except Exception as e:
        cprint(f"ERROR: Failed to read /etc/passwd: {e}", "red", file=sys.stderr)
    return passwd_data

def get_confirmation(prompt: str ="Do you want to proceed? (y/n): ") -> bool:
    while True:
        response = input(prompt).strip().lower()
        if response in ('y', 'yes'):
            return True
        elif response in ('n', 'no'):
            return False
        else:
            print("Please respond with 'y' or 'n'.")

def list_locked_users(verbose: bool =False) -> list[str]:
    __passwd_data = load_etc_passwd(verbose)
    __non_interactive_shells = ('/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/bin/sync')
    locked_users = []
    try:
        result = subprocess.run(
            ["passwd", "-S", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "L":
                    # We don't care if users that can't login interactively are locked, so we check their shell as well.
                    if __passwd_data.get(parts[0], {}).get('shell') not in __non_interactive_shells:
                        locked_users.append(parts[0])
        else:
            cprint(f"ERROR: Failed to list users: {result.stderr}", "red", file=sys.stderr)
    except FileNotFoundError:
        cprint("ERROR: 'passwd' command not found.", "red", file=sys.stderr)
    return locked_users

def get_distro(verbose: bool =False) -> str:
    try:
        result = subprocess.run(
            ["lsb_release", "-is"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            distro = result.stdout.strip().lower()
            _verbose_print(verbose, f"Detected distribution: {distro}")
            return distro
        else:
            cprint(f"ERROR: Failed to detect distribution: {result.stderr}", "red", file=sys.stderr)
    except FileNotFoundError:
        _warn_print(verbose, "ERROR: 'lsb_release' command not found. Attempting to access '/etc/os-release' for distribution information.")
        try:
            with open("/etc/os-release", "r", encoding='utf-8') as os_release_file:
                for line in os_release_file:
                    if line.startswith("ID="):
                        distro = line.split("=")[1].strip().strip('"').lower()
                        _verbose_print(verbose, f"Detected distribution: {distro}")
                        return distro
        except FileNotFoundError:
            cprint("ERROR: '/etc/os-release' file not found.", "red", file=sys.stderr)
    return "unknown"

def load_hardening_config(hardening_config: str | Path =Path("./hardening.conf"), verbose: bool =False) -> dict:
    _verbose_print(verbose, f"Loading the hardening config.")
    config = {}
    # try:
    with open(hardening_config, 'r', encoding="utf-8") as conf_file:
        config = json.load(conf_file)
        _verbose_pretty_print(verbose, config)
    # except FileNotFoundError():
    #     cprint(f"Could not file the hardening config ({hardening_config})!", "red", file=sys.stderr)
    #     sys.ext(1)
    return config

def sed_file(target_file_path: str | Path, search_pattern: str, replacement_text: str, verbose: bool =False, dryrun: bool =False) -> bool:
    """
    Finds a pattern within a file and replaces it atomincally using a temporary file.

    This function reads a file line by line to minimize memory consumption, making it 
    highly efficient for large test streams.  It searchs for a regular expression
    pattern.  When fiound, it repklaces the matched text with the provided replacement.
    To encure data integrity, the modified stream is written to a temporary file
    in the same directory.  Once successfully written, the temporary file atomically
    overwritten the orifinal file, preventing corruption if the script terminates mid-way.

    Args:
        target_file_path: The absolute or relative path to the file being modified.
        search_pattern: The regular excpression patter to find within the text.
        replacement_text: The string that will replace the matched pattern.
        verbose: Explains what the function is doing during execution.
        dryrun: Simulates the operation without making actual file changes.

    Returns: 
        A bopolean indicating whether any pattern match and replacement occurred.
    """
    compiled_regex = re.compile(search_pattern)
    match_found = False
    file_directory = os.path.dirname(target_file_path)

    _verbose_print(verbose, f"Opening file for stream processing: {target_file_path}")

    # We open a temporary file in the same directory to guarantee an atomic os.replace later.
    # delete=False is required because we manually rename and replace the file.
    with(
        open(target_file_path, "r", encoding="utf-8") as regular_file, 
        tempfile.NamedTemporaryFile(
            "w", dir=file_directory, delete=False, encoding="utf-8"
        ) as temporary_file,
    ):

        for line_number, current_line in enumerate(regular_file, start=1):
            if compiled_regex.search(current_line):
                match_found = True
                # Perform the regec substitution on the current line string stream
                modified_line = compiled_regex.sub(
                    replacement_text, current_line
                )
                # uncomment if commented
                if '#' in modified_line:
                    modified_line = modified_line.replace('#', '')
                if verbose or dryrun:
                    print(f"[MATCH] Line {line_number} matched pattern: '{search_pattern}'")
                    print(f"  Original: {current_line.strip()}")
                    print(f"  Proposed: {modified_line.strip()}")
                temporary_file.write(modified_line)
            else:
                temporary_file.write(current_line)
    if not match_found:
        _verbose_print(verbose, f"No matching patterns found.  File remains unmodified.")
        os.unlink(temporary_file.name)
        return False

    if dryrun:
        _dryrun_print(f"Dry run active: Rolling back changes and removing temp file.")
        os.unlink(temporary_file.name)
        return True
    
    _verbose_print(f"Atomically overwriting original file: {target_file_path}")
    os.replace(temporary_file.name, target_file_path)
    return True

#endregion

#region Hardening Functions

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

def install_dnf_package(enabled: bool, package_name: str) -> bool:
    try:
        # Runs 'dnf install -y <package_name> safely
        subprocess.run(
            ["dnf", "install", "-y", package_name],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"Successfully installed {package_name}")
        return True
    except subprocess.CalledProcessError as _error:
        cprint(f"ERROR: Installation failed: {_error}", "red", file=sys.stderr)
        return False
    except FileNotFoundError:
        cprint("ERROR: 'dnf' command not found. Ensure DNF is installed on your system.", "red", file=sys.stderr)
        return False

def disable_coredump(verbose: bool =False) -> None:
    etc_security_limits_conf = '/etc/security/limits.conf'
    coredump_content = [ "* soft core 0\n", "* hard core 0\n", "# End of file\n" ]
    for content in coredump_content:
        _append_file(etc_security_limits_conf, content, verbose)

def write_custom_profile_entry(test_id: str, verbose: bool) -> None:
    if not os.path.exists(LYNIS_CUSTOM_PROFILE):
        _warn_print(verbose, f"Custom profile file does not exist at {LYNIS_CUSTOM_PROFILE}. Creating it...")
        LYNIS_CUSTOM_PROFILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(LYNIS_CUSTOM_PROFILE, "r", encoding='utf-8') as custom_profile:
            existing_entries = custom_profile.readlines()

        for line in existing_entries:
            stripped_line = line.strip()
            if stripped_line == f"skip-test {test_id}" or stripped_line.startswith(f"skip-test {test_id} "):
                _verbose_print(verbose, f"Custom profile already contains skip-test entry for {test_id}. Skipping append.")
                return

        with open(LYNIS_CUSTOM_PROFILE, "a", encoding='utf-8') as custom_profile:
            custom_profile.write(f"skip-test {test_id}\n")
    except FileNotFoundError:
        cprint(f"ERROR: Custom profile file not found at {LYNIS_CUSTOM_PROFILE}.", "red", file=sys.stderr)
    except Exception as e:
        cprint(f"ERROR: Failed to write to custom profile: {e}", "red", file=sys.stderr)

def update_etc_hosts(verbose: bool =False) -> None:
    hosts_file_path = Path("/etc/hosts")
    try:
        with open(hosts_file_path, "r", encoding='utf-8') as hosts_file:
            lines = hosts_file.readlines()

        _local_ip = get_local_ip(verbose)
        _hostname = socket.gethostname()
        updated_lines = []
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line.startswith(_local_ip):
                updated_lines.append(f"{_local_ip} {_hostname}\n")
    except Exception as e:
        cprint(f"ERROR: Failed to update /etc/hosts: {e}", "red", file=sys.stderr)

def harden_file_permissions(file_path: str, owner: str, mode: int, verbose: bool =False) -> None:
    try:
        if not os.path.exists(file_path):
            _warn_print(verbose, f"File {file_path} does not exist. Skipping permission hardening.")
            return

        # Change ownership
        uid = int(subprocess.check_output(["id", "-u", owner]).strip())
        gid = int(subprocess.check_output(["id", "-g", owner]).strip())
        os.chown(file_path, uid, gid)

        # Change permissions
        os.chmod(file_path, mode)

        _verbose_print(verbose, f"Successfully hardened permissions for {file_path}: owner={owner}, mode={oct(mode)}")
    except Exception as e:
        cprint(f"ERROR: Failed to harden permissions for {file_path}: {e}", "red", file=sys.stderr)

#endregion

def main():
    __uid = os.getuid()
    __euid = os.geteuid()

    if not __uid == 0 and not __euid == 0:
        _warn_print(True, f"You should run this as root.")
        return sys.exit(1)
    
    arguments = _parse_arguments()
    if arguments.debug:
        arguments.verbose = True

    if not os.path.exists(LYNIS_CUSTOM_PROFILE):
        _warn_print(arguments.verbose, f"The lynis custom profile path does not exist or is not complete.  Check {LYNIS_CUSTOM_PROFILE}.")
    else:
        _verbose_print(arguments.verbose, f"{LYNIS_CUSTOM_PROFILE} already exists.")

    if arguments.alt_lynis_report:
        lynis_report = read_lynis_report(arguments.alt_lynis_report, arguments.verbose)
    else:
        lynis_report = read_lynis_report()

    _verbose_pretty_print(arguments.debug, lynis_report)

    hardening_config = load_hardening_config()

    # These checks (and corrections) are in no particular order.  They were written
    # in the order in which they were experienced on my test systems.

    #region Print Report Metadata Header
    report_start = datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=ZoneInfo("UTC"))
    report_end = datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=ZoneInfo("UTC"))
    if 'report_datetime_start' in lynis_report:
        report_start = datetime.datetime.strptime(lynis_report['report_datetime_start'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo("UTC"))
    if 'report_datetime_end' in lynis_report:
        report_end = datetime.datetime.strptime(lynis_report['report_datetime_end'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo("UTC"))

    print(f"Report Start: {report_start}\tReport End: {report_end}")
    print(f"Report Duration: {report_end - report_start}")
    print(f"Report version: {".".join([str(lynis_report['report_version_major']), str(lynis_report['report_version_minor'])])}\tLynis version: {lynis_report['lynis_version']}")
    #endregion

    has_run = {
        'SSH-7408': False
    }
    not_run = { }
    package_installs_status = {}
    os_distro = get_distro(arguments.verbose)

    #region: Warnings
    for warning in lynis_report.get("warning[]", []):
        _warn_print(arguments.verbose, f"Warning: {warning.description} (Test ID: {warning.test_id})")
    
        #region FIRE-4512 - Install and Configure Firewall
        if warning.test_id == "FIRE-4512":
            # iptables/nftables is installed but not configured.  Make sure the management/control app
            # appropriate for the distro is installed, and setup some basic rules.
            if os_distro in DEBIAN_LIKE:
                if not is_apt_package_installed("ufw"):
                    package_installs_status["ufw"] = install_apt_package(arguments.verbose, "ufw")
                else:
                    _verbose_print(arguments.verbose, f"Package 'ufw' is already installed.")
                    package_installs_status["ufw"] = True
            elif os_distro in RHEL_LIKE:
                if not is_dnf_package_installed("firewalld"):
                    package_installs_status["firewalld"] = install_dnf_package(arguments.verbose, "firewalld")
                else:
                    _verbose_print(arguments.verbose, f"Package 'firewalld' is already installed.")
                    package_installs_status["firewalld"] = True
        #endregion
    #endregion

    confirmed = arguments.yes_all
    for suggestion in lynis_report.get("suggestion[]", []):
        print(f"Suggestion: {suggestion.description} (Test ID: {suggestion.test_id})")
        if suggestion.test_id == "BOOT-5264":
            _verbose_print(arguments.verbose, f"Running 'systemd-analyze security' for each service...")
            try:
                result = subprocess.run(
                    ["systemd-analyze", "security"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0:
                    _verbose_print(arguments.verbose, f"Successfully ran 'systemd-analyze security'. Output:\n{result.stdout}")
                else:
                    cprint(f"ERROR: Failed to run 'systemd-analyze security': {result.stderr}", "red", file=sys.stderr)
            except FileNotFoundError:
                cprint("ERROR: 'systemd-analyze' command not found. Ensure systemd is installed.", "red", file=sys.stderr)

        #region KRNL-5820: Disable core dumps
        if suggestion.test_id == "KRNL-5820":
            if arguments.dry_run:
                _dryrun_print("Would disable core dumps.")
            elif not confirmed:
                confirmed = get_confirmation("Do you want to disable core dumps? (y/n): ")
                if not confirmed:
                    confirmed = get_confirmation("Would you like to add this check as an exception in the custom profile? (y/n): ")
                    if confirmed:
                        write_custom_profile_entry(suggestion.test_id, arguments.verbose)
                    continue
                _verbose_print(arguments.verbose, f"Disabling core dumps...")
                disable_coredump(arguments.verbose)
        #endregion

        #region AUTH-9262: Install a PAM module for password strength checking
        if suggestion.test_id == "AUTH-9262":
            if get_distro(arguments.verbose) in DEBIAN_LIKE:
                if arguments.dry_run:
                    _dryrun_print("Would install 'libpam-cracklib' package.")
                else:
                    if not is_apt_package_installed("libpam-cracklib"):
                        package_installs_status["libpam-cracklib"] = install_apt_package(arguments.verbose, "libpam-cracklib")
                    else:
                        _verbose_print(arguments.verbose, f"Package 'libpam-cracklib' is already installed.")
                        package_installs_status["libpam-cracklib"] = True
            elif get_distro(arguments.verbose) in RHEL_LIKE:
                if arguments.dry_run:
                    _dryrun_print("Would install 'cracklib' package.")
                else:
                    if not is_dnf_package_installed("cracklib"):
                        package_installs_status["cracklib"] = install_dnf_package(arguments.verbose, "cracklib")
                    else:
                        _verbose_print(arguments.verbose, f"Package 'cracklib' is already installed.")
                    package_installs_status["cracklib"] = True
        #endregion

        #region AUTH-9284: Unlock locked users
        if suggestion.test_id == "AUTH-9284":
            locked_users = list_locked_users(arguments.verbose)
            if locked_users:
                _warn_print(arguments.verbose, f"Locked users found: {', '.join(locked_users)}")
                if arguments.dry_run:
                    _dryrun_print(f"Would unlock the following users: {', '.join(locked_users)}")
                elif not confirmed:
                    confirmed = get_confirmation(f"Do you want to unlock the following users: {', '.join(locked_users)}? (y/n): ")
                    if not confirmed:
                        confirmed = get_confirmation("Would you like to add this check as an exception in the custom profile? (y/n): ")
                        if confirmed:
                            write_custom_profile_entry(suggestion.test_id, arguments.verbose)
                        continue
                    for user in locked_users:
                        try:
                            result = subprocess.run(
                                ["passwd", "-u", user],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True
                            )
                            if result.returncode == 0:
                                _verbose_print(arguments.verbose, f"Successfully unlocked user '{user}'.")
                            else:
                                cprint(f"ERROR: Failed to unlock user '{user}': {result.stderr}", "red", file=sys.stderr)
                        except FileNotFoundError:
                            cprint("ERROR: 'passwd' command not found. Ensure it is available on your system.", "red", file=sys.stderr)
            else:
                _verbose_print(arguments.verbose, f"No locked users found.")
            #endregion

        #region AUTH-9328: Set umask
        if suggestion.test_id == "AUTH-9328":
            cprint(f"WARNING: Setting the umask to the suggested value (027) may have unintended consequences. Please review your system's requirements before proceeding.", "yellow", file=sys.stderr)
            cprint(f"Current umask: {os.umask(0):03o}", "yellow", file=sys.stderr)
            cprint(f"Adding this to the custom profile, since unwittingly changing the umask can break things.", "yellow", file=sys.stderr)
            write_custom_profile_entry(suggestion.test_id, arguments.verbose)
        #endregion

        #region NAME-4404: Update /etc/hosts with local IP and hostname
        if suggestion.test_id == "NAME-4404":
            if arguments.dry_run:
                _dryrun_print("Would update /etc/hosts with local IP and hostname.")
            elif not confirmed:
                confirmed = get_confirmation("Do you want to update /etc/hosts with local IP and hostname? (y/n): ")
                if not confirmed:
                    confirmed = get_confirmation("Would you like to add this check as an exception in the custom profile? (y/n): ")
                    if confirmed:
                        write_custom_profile_entry(suggestion.test_id, arguments.verbose)
                    continue
                _verbose_print(arguments.verbose, f"Updating /etc/hosts with local IP and hostname...")
                update_etc_hosts(arguments.verbose)
        #endregion

        #region PKGS-7370: Install debsums utility
        if suggestion.test_id == "PKGS-7370":
            # Assume we're on a DEBIAN_LIKE system since debsums is a Debian utility.
            if arguments.dry_run:
                _dryrun_print("Would install 'debsums' package.")
            else:
                if not is_apt_package_installed("debsums"):
                    package_installs_status["debsums"] = install_apt_package(arguments.verbose, "debsums")
                else:
                    _verbose_print(arguments.verbose, f"Package 'debsums' is already installed.")
                    package_installs_status["debsums"] = True
        #endregion

        #region PKGS-7394: Install `apt-show-versions` utility
        if suggestion.test_id == "PKGS-7394":
            # Assume we're on a DEBIAN_LIKE system since apt-show-versions is a Debian utility.
            if arguments.dry_run:
                _dryrun_print("Would install 'apt-show-versions' package.")
            else:
                if not is_apt_package_installed("apt-show-versions"):
                    package_installs_status["apt-show-versions"] = install_apt_package(arguments.verbose, "apt-show-versions")
                else:
                    _verbose_print(arguments.verbose, f"Package 'apt-show-versions' is already installed.")
                    package_installs_status["apt-show-versions"] = True
        #endregion
        
        #region HRDN-7222: Harden permissions on compilers
        if suggestion.test_id == "HRDN-7222":
            _warn_print(arguments.verbose, f"Hardening permissions on compilers may break some software builds. Please review your system's requirements before proceeding.")
            if arguments.dry_run:
                _dryrun_print(f"Would harden permissions on compilers.")
            elif not confirmed:
                confirmed = get_confirmation(f"Do you want to harden permissions on compilers? (y/n): ")
                if not confirmed:
                    confirmed = get_confirmation("Would you like to add this check as an exception in the custom profile? (y/n): ")
                    if confirmed:
                        write_custom_profile_entry(suggestion.test_id, arguments.verbose)
                    continue
                # Here you would add the logic to actually harden permissions on compilers if confirmed.
                for compiler in COMPILER_PATHS:
                    try:
                        harden_file_permissions(compiler, "root", 0o700, arguments.verbose)
                        _verbose_print(arguments.verbose, f"Permissions hardened for compiler '{compiler}' (owner=root, mode=0o700).")
                    except Exception as e:
                        cprint(f"ERROR: Failed to harden permissions for compiler '{compiler}': {e}", "red", file=sys.stderr)
        #endregion 

        #region NETW-3200: Disable dccp, sctp, rds, tipc
        if suggestion.test_id == "NETW-3200":
            _verbose_pretty_print(arguments.debug, suggestion)
            _match = re.search(r"Determine if protocol \'(dccp|sctp|rds|tipc)\' is really needed", suggestion.description)
            if _match:
                _protocol = _match.group(1).strip()
            else:
                _warn_print(f"Didn't match a recognized protocol in string: {suggestion.description}")
            if arguments.dry_run:
                _dryrun_print(f"Disabling {_protocol}")
            else:
                if not confirmed:
                    confirmed = get_confirmation(f"Would you like to disable the {_protcol} protocol? (y/n):f")
                    if not confirmed:
                        confirmed = get_confirmation("Would you like to add this check as an exception in the custom profile? (y/n): ")
                        if confirmed:
                            write_custom_profile_entry(suggestion.test_id, arguments.verbose)
                        continue
                _verbose_print(arguments.verbose, f"Disabling the '{_protocol}' protocol and kernel module.")
                for content in [ f"install {_protocol} /bin/false", f"blacklist {_protocol}"]:
                    _append_file(f"/etc/modprobe.d/{_protocol}.conf", content, arguments.verbose)
                harden_file_permissions(f"/etc/modprobe.d/{_protocol}.conf", "root", 0o700, arguments.verbose)
        #endregion

        #region FILE-7524: Harden file permissions
        # The tricky part with this one is we don't nececessarily know what files need correcting.
        # Maybe we'll come back to this. lol
        #endregion

        #region SSH-7408: Harden SSH config
        # also tricky....
        if suggestion.test_id == "SSH-7408":
            _verbose_print(arguments.verbose, f"Hardening SSH settings.")
            _verbose_pretty_print(arguments.verbose, hardening_config['SSH-7408']['secure_sshd_config_settings'])
            for pattern_key, value in hardening_config['SSH-7408']['secure_sshd_config_settings'].items():
                if isinstance(value, str):

                    replacement_text = f"{pattern_key} {value.lower()}"
                else:
                    replacement_text = f"{pattern_key} {value}"
                # TODO: need to account for patterns moatching commented lines (and uncomment)
                # TODO: need to check if the matched pattern already has the correct value.
                sed_file("../sshd_config", pattern_key, replacement_text, arguments.verbose, arguments.dry_run)

if __name__=='__main__':
    raise SystemExit(main())