"""
Log Analyzer Using Regular Expressions
Theory of Computation Activity - Log File Analysis

Log Format: YYYY-MM-DD HH:MM:SS LEVEL STATUS_CODE IP_ADDRESS
"""

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Optional


TIMESTAMP = r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
OCTET = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = rf"({OCTET}\.){{3}}{OCTET}"
LEVEL = r"\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b"
STATUS = r"[1-5]\d{2}"
ERROR_ENTRY = rf"^{TIMESTAMP} ERROR {STATUS} {IPV4}$"

LINE = re.compile(rf"^(?P<ts>{TIMESTAMP}) (?P<level>{LEVEL}) (?P<code>{STATUS}) (?P<ip>{IPV4})$")
ERROR_RE = re.compile(ERROR_ENTRY)


@dataclass
class LogRecord:
    line_number: int
    raw_line: str
    timestamp: str
    level: str
    code: str
    ip: str
    is_error: bool


def diagnose(line: str) -> str:
    """Analyze an invalid log line and determine the specific reason for failure."""
    parts = line.split(" ")
    if len(parts) != 5:
        return "expected 5 fields: date time level code ip"

    timestamp_str = f"{parts[0]} {parts[1]}"
    if not re.fullmatch(TIMESTAMP, timestamp_str):
        return "invalid timestamp"
    if not re.fullmatch(LEVEL, parts[2]):
        return "unknown log level"
    if not re.fullmatch(STATUS, parts[3]):
        return "invalid status code"
    if not re.fullmatch(IPV4, parts[4]):
        return "invalid IPv4 address"

    return "does not match the log format"


def check_line(line: str) -> None:
    """Validate and display extracted fields or failure diagnostics for a single log line."""
    cleaned_line = line.strip()
    match = LINE.match(cleaned_line)

    print(f"Input  : {cleaned_line}")
    if match:
        fields = match.groupdict()
        is_error = "YES" if ERROR_RE.match(cleaned_line) else "NO"
        print("Result : VALID")
        print(f"  Timestamp   : {fields['ts']}")
        print(f"  Level       : {fields['level']}")
        print(f"  Status code : {fields['code']}")
        print(f"  IP address  : {fields['ip']}")
        print(f"  Error entry : {is_error}")
    else:
        print("Result : INVALID")
        print(f"  Reason      : {diagnose(cleaned_line)}")


def analyse_file(file_path: str, target_code: str = "404") -> None:
    """Parse, validate, and summarize an entire log file."""
    path = Path(file_path)
    if not path.is_file():
        print(f"Error: File '{file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    with path.open("r", encoding="utf-8") as file:
        raw_lines = [line.rstrip("\n") for line in file if line.strip()]

    records: list[LogRecord] = []
    error_entries: list[tuple[int, str]] = []
    invalid_lines: list[tuple[int, str, str]] = []

    for line_number, raw_line in enumerate(raw_lines, start=1):
        match = LINE.match(raw_line)
        if match:
            fields = match.groupdict()
            is_error = bool(ERROR_RE.match(raw_line))
            records.append(
                LogRecord(
                    line_number=line_number,
                    raw_line=raw_line,
                    timestamp=fields["ts"],
                    level=fields["level"],
                    code=fields["code"],
                    ip=fields["ip"],
                    is_error=is_error,
                )
            )
            if is_error:
                error_entries.append((line_number, raw_line))
        else:
            invalid_lines.append((line_number, raw_line, diagnose(raw_line)))

    separator = "-" * 66

    print("EXTRACTED RECORDS")
    print(separator)
    print(f"{'Timestamp':<21}{'Level':<10}{'Code':<6}{'IP address'}")
    print(separator)
    for record in records:
        print(f"{record.timestamp:<21}{record.level:<10}{record.code:<6}{record.ip}")

    print("\nERROR ENTRIES")
    print(separator)
    for line_number, raw_line in error_entries:
        print(f"line {line_number:<3} {raw_line}")

    print("\nINVALID LINES")
    print(separator)
    for line_number, raw_line, reason in invalid_lines:
        print(f"line {line_number:<3} {raw_line}   -> {reason}")

    level_counts = Counter(record.level for record in records)
    matched_code_count = sum(1 for record in records if record.code == target_code)
    unique_ips_count = len({record.ip for record in records})
    level_summary = ", ".join(f"{k}={v}" for k, v in sorted(level_counts.items()))

    print("\nSUMMARY")
    print(separator)
    print(f"Total lines processed   : {len(raw_lines)}")
    print(f"Valid lines             : {len(records)}")
    print(f"Invalid lines           : {len(invalid_lines)}")
    print(f"ERROR entries           : {len(error_entries)}")
    print(f"{'Entries with code ' + target_code:<24}: {matched_code_count}")
    print(f"Unique IP addresses     : {unique_ips_count}")
    print(f"Entries per level       : {level_summary}")


def interactive_mode() -> None:
    """Read log lines from standard input interactively until an empty line is entered."""
    print("Enter a log line (empty line to quit):")
    while True:
        try:
            line = input("> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not line.strip():
            break
        check_line(line)
        print()


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Log Analyzer using Regular Expressions (Theory of Computation)"
    )
    parser.add_argument("logfile", nargs="?", help="Path to log file to analyze")
    parser.add_argument("--check", metavar="LINE", help="Check and diagnose a single log line")
    parser.add_argument(
        "--interactive", action="store_true", help="Launch interactive verification mode"
    )
    parser.add_argument(
        "--code", default="404", help="HTTP status code to count in summary (default: 404)"
    )
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.check:
        check_line(args.check)
    elif args.interactive:
        interactive_mode()
    elif args.logfile:
        analyse_file(args.logfile, target_code=args.code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
