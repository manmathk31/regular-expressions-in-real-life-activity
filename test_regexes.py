"""
Regex test runner - 5 regexes x (5 valid + 5 invalid) = 50 test cases.
Run:  python test_regexes.py            (all regexes)
      python test_regexes.py 2          (only Regex 2)
"""
import re
import sys
from log_analyzer import TIMESTAMP, IPV4, LEVEL, STATUS, ERROR_ENTRY

TESTS = {
    1: ("Timestamp", TIMESTAMP, [
        ("2026-10-28 10:15:20", True),
        ("2026-01-01 00:00:00", True),
        ("2025-12-31 23:59:59", True),
        ("2026-02-14 09:05:45", True),
        ("2024-07-15 18:30:00", True),
        ("2026-13-28 10:15:20", False),
        ("2026-10-32 10:15:20", False),
        ("2026-10-28 24:15:20", False),
        ("2026/10/28 10:15:20", False),
        ("2026-10-28 10:15", False),
    ]),
    2: ("IPv4 address", IPV4, [
        ("192.168.1.10", True),
        ("10.0.0.8", True),
        ("255.255.255.255", True),
        ("0.0.0.0", True),
        ("172.16.254.1", True),
        ("256.1.1.1", False),
        ("192.168.1", False),
        ("192.168.1.10.5", False),
        ("192.168.01.1", False),
        ("192.168.1.abc", False),
    ]),
    3: ("Log level", LEVEL, [
        ("INFO", True),
        ("WARNING", True),
        ("ERROR", True),
        ("DEBUG", True),
        ("CRITICAL", True),
        ("error", False),
        ("ERRORS", False),
        ("WARN", False),
        ("FATAL", False),
        ("ERR0R", False),
    ]),
    4: ("HTTP status code", STATUS, [
        ("200", True),
        ("404", True),
        ("500", True),
        ("301", True),
        ("503", True),
        ("99", False),
        ("600", False),
        ("2000", False),
        ("4O4", False),
        ("000", False),
    ]),
    5: ("Error log entry", ERROR_ENTRY, [
        ("2026-10-28 10:16:05 ERROR 404 192.168.1.15", True),
        ("2026-10-28 10:17:42 ERROR 500 10.0.0.8", True),
        ("2026-10-28 11:02:19 ERROR 503 172.16.0.4", True),
        ("2026-10-29 00:00:01 ERROR 403 203.0.113.77", True),
        ("2026-11-02 23:59:59 ERROR 502 192.168.10.200", True),
        ("2026-10-28 10:15:20 INFO 200 192.168.1.10", False),
        ("2026-10-28 10:16:05 error 404 192.168.1.15", False),
        ("2026-10-28 10:16:05 ERRORS 404 192.168.1.15", False),
        ("2026-10-28 10:16:05 ERROR 404 192.168.1.256", False),
        ("ERROR 404 192.168.1.15", False),
    ]),
}


def run(selected=None):
    total = passed = 0
    for n, (name, pattern, cases) in TESTS.items():
        if selected and n != selected:
            continue
        print(f"\nRegex {n}: {name}")
        print("-" * 78)
        print(f"{'No.':<4}{'Input string':<46}{'Expected':<10}{'Actual':<9}{'Result'}")
        for i, (text, expected) in enumerate(cases, start=1):
            actual = re.fullmatch(pattern, text) is not None
            ok = actual == expected
            total += 1
            passed += ok
            print(f"{i:<4}{text:<46}{'Valid' if expected else 'Invalid':<10}"
                  f"{'Valid' if actual else 'Invalid':<9}{'PASS' if ok else 'FAIL'}")
    print(f"\nTotal: {passed}/{total} test cases passed")


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else None)
