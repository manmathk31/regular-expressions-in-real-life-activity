"""
Log Analyzer Using Regular Expressions
Theory of Computation activity - Log File Analysis
Log line format:  YYYY-MM-DD HH:MM:SS LEVEL STATUS_CODE IP_ADDRESS

Usage:
  python log_analyzer.py sample_logs.txt               analyse a whole log file
  python log_analyzer.py --check "<one log line>"      check one line (Valid / Invalid)
  python log_analyzer.py --interactive                 type lines one by one
Options:
  --code 404      status code to count in the summary (default 404)
"""
import re
import sys
import argparse

# ---------- The five regular expressions ----------
# Regex 1: timestamp  YYYY-MM-DD HH:MM:SS
TIMESTAMP = r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
# Regex 2: IPv4 address (each part 0-255, no leading zeros)
OCTET = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = "(" + OCTET + r"\.){3}" + OCTET
# Regex 3: log level
LEVEL = r"\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b"
# Regex 4: HTTP status code (100-599)
STATUS = r"[1-5]\d{2}"
# Regex 5: a complete ERROR log entry
ERROR_ENTRY = "^" + TIMESTAMP + " ERROR " + STATUS + " " + IPV4 + "$"

# Full log line, with named groups to extract each field
LINE = re.compile(
    "^(?P<ts>" + TIMESTAMP + ") (?P<level>" + LEVEL + ") (?P<code>" + STATUS + ") (?P<ip>" + IPV4 + ")$"
)
ERROR_RE = re.compile(ERROR_ENTRY)


def diagnose(line):
    """Return the reason why a line is invalid (checks each field with its own regex)."""
    parts = line.split(" ")
    if len(parts) != 5:
        return "expected 5 fields: date time level code ip"
    if not re.fullmatch(TIMESTAMP, parts[0] + " " + parts[1]):
        return "invalid timestamp"
    if not re.fullmatch(LEVEL, parts[2]):
        return "unknown log level"
    if not re.fullmatch(STATUS, parts[3]):
        return "invalid status code"
    if not re.fullmatch(IPV4, parts[4]):
        return "invalid IPv4 address"
    return "does not match the log format"


def check_line(line):
    """Print Valid / Invalid for one log line, with the extracted fields."""
    line = line.strip()
    m = LINE.match(line)
    print("Input  :", line)
    if m:
        print("Result : VALID")
        print("  Timestamp   :", m.group("ts"))
        print("  Level       :", m.group("level"))
        print("  Status code :", m.group("code"))
        print("  IP address  :", m.group("ip"))
        print("  Error entry :", "YES" if ERROR_RE.match(line) else "NO")
    else:
        print("Result : INVALID")
        print("  Reason      :", diagnose(line))


def analyse_file(path, wanted_code):
    with open(path, encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]

    records, invalid, errors = [], [], []
    for number, line in enumerate(lines, start=1):
        m = LINE.match(line)
        if m:
            records.append(m.groupdict())
            if ERROR_RE.match(line):
                errors.append((number, line))
        else:
            invalid.append((number, line, diagnose(line)))

    print("EXTRACTED RECORDS")
    print("-" * 66)
    print(f"{'Timestamp':<21}{'Level':<10}{'Code':<6}{'IP address'}")
    print("-" * 66)
    for r in records:
        print(f"{r['ts']:<21}{r['level']:<10}{r['code']:<6}{r['ip']}")

    print("\nERROR ENTRIES")
    print("-" * 66)
    for number, line in errors:
        print(f"line {number:<3} {line}")

    print("\nINVALID LINES")
    print("-" * 66)
    for number, line, reason in invalid:
        print(f"line {number:<3} {line}   -> {reason}")

    levels = {}
    for r in records:
        levels[r["level"]] = levels.get(r["level"], 0) + 1
    with_code = sum(1 for r in records if r["code"] == wanted_code)

    print("\nSUMMARY")
    print("-" * 66)
    print("Total lines processed   :", len(lines))
    print("Valid lines             :", len(records))
    print("Invalid lines           :", len(invalid))
    print("ERROR entries           :", len(errors))
    print(f"{'Entries with code ' + wanted_code:<24}:", with_code)
    print("Unique IP addresses     :", len({r['ip'] for r in records}))
    print("Entries per level       :", ", ".join(f"{k}={v}" for k, v in sorted(levels.items())))


def main():
    ap = argparse.ArgumentParser(description="Log analyser using regular expressions")
    ap.add_argument("logfile", nargs="?", help="log file to analyse")
    ap.add_argument("--check", metavar="LINE", help="check a single log line")
    ap.add_argument("--interactive", action="store_true", help="type log lines one by one")
    ap.add_argument("--code", default="404", help="status code to count (default 404)")
    args = ap.parse_args()

    if args.check:
        check_line(args.check)
    elif args.interactive:
        print("Enter a log line (empty line to quit):")
        while True:
            line = input("> ")
            if not line.strip():
                break
            check_line(line)
            print()
    elif args.logfile:
        analyse_file(args.logfile, args.code)
    else:
        ap.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
