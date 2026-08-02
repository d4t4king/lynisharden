#!/usr/bin/env python3

import os
import apt
import ast
import sys
import pprint
import argparse
import datetime
import subprocess
from termcolor import cprint
from typing import Literal,Any
from dataclasses import dataclass

LYNIS_CUSTOM_PROFILE='/etc/lynis/custom.prf'
LYNIS_REPORT_PATH='/var/log/lynis-report.dat'
LYNIS_LOG_PATH='/var/log/lynis.log'

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

def parse_arguments() -> argparse.Namespace:
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

def _append_file(file_path: str, content: str, verbose: bool =False) -> None:
    try:
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(content)
        _verbose_print(verbose, f"Appended content to {file_path}.")
    except FileNotFoundError:
        cprint(f"ERROR: File {file_path} not found.", "red", file=sys.stderr)
    except Exception as e:
        cprint(f"ERROR: Failed to append to {file_path}: {e}", "red", file=sys.stderr)

def get_confirmation(prompt: str ="Do you want to proceed? (y/n): ") -> bool:
    while True:
        response = input(prompt).strip().lower()
        if response in ('y', 'yes'):
            return True
        elif response in ('n', 'no'):
            return False
        else:
            print("Please respond with 'y' or 'n'.")

def disable_coredump(verbose: bool =False) -> None:
    etc_security_limits_conf = '/etc/security/limits.conf'
    coredump_content = [ "* soft core 0\n", "* hard core 0\n", "# End of file\n" ]
    for content in coredump_content:
        _append_file(etc_security_limits_conf, content, verbose)

def _load_etc_passwd(verbose: bool =False) -> dict[str, dict[str, str]]:
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

def list_locked_users(verbose: bool =False) -> list[str]:
    __passwd_data = _load_etc_passwd(verbose)
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

def write_custom_profile_entry(test_id: str, verbose: bool) -> None:
    try:
        with open("/etc/lynis/custom.prf", "a", encoding='utf-8') as custom_profile:
            custom_profile.write(f"skip-test {test_id}\n")
    except FileNotFoundError:
        cprint(f"ERROR: Custom profile file not found at /etc/lynis/custom.prf.", "red", file=sys.stderr)
    except Exception as e:
        cprint(f"ERROR: Failed to write to custom profile: {e}", "red", file=sys.stderr)

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

    if arguments.alt_lynis_report:
        lynis_report = read_lynis_report(arguments.alt_lynis_report, arguments.verbose)
    else:
        lynis_report = read_lynis_report()

    _verbose_pretty_print(arguments.debug, lynis_report)

    # These checks (and corrections) are in no particular order.  They were written
    # in the order in which they were experienced on my test systems.

    #region Print Header
    print(f"Report Start: {lynis_report['report_datetime_start']}\tReport End: {lynis_report['report_datetime_end']}")
    report_start = datetime.datetime.strptime(lynis_report['report_datetime_start'], "%Y-%m-%d %H:%M:%S")
    report_end = datetime.datetime.strptime(lynis_report['report_datetime_end'], "%Y-%m-%d %H:%M:%S")
    print(f"Report Duration: {report_end - report_start}")
    print(f"Report version: {".".join([str(lynis_report['report_version_major']), str(lynis_report['report_version_minor'])])}\tLynis version: {lynis_report['lynis_version']}")
    #endregion

    # Start with the warnings
    for warning in lynis_report.get("warning[]", []):
        _warn_print(arguments.verbose, f"Warning: {warning.description} (Test ID: {warning.test_id})")
    
    package_installs_status = {}
    if not is_apt_package_installed("ufw"):
        package_installs_status["ufw"] = install_apt_package(arguments.verbose, "ufw")
    else:
        _verbose_print(arguments.verbose, f"Package 'ufw' is already installed.")
        package_installs_status["ufw"] = True

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
                _verbose_print(arguments.verbose, f"Dry run: Would disable core dumps.")
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

        #region AUTH-9284: Unlock locked users
        if suggestion.test_id == "AUTH-9284":
            locked_users = list_locked_users(arguments.verbose)
            if locked_users:
                _warn_print(arguments.verbose, f"Locked users found: {', '.join(locked_users)}")
                if arguments.dry_run:
                    _verbose_print(arguments.verbose, f"Dry run: Would unlock the following users: {', '.join(locked_users)}")
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

if __name__=='__main__':
    raise SystemExit(main())