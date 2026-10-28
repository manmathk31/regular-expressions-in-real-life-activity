"""
Regular Expression Test Suite
Theory of Computation Activity - 5 Regexes x (5 Valid + 5 Invalid) = 50 Test Cases

Usage:
  python test_regexes.py        Run all test cases
  python test_regexes.py 2      Run only test cases for Regex 2
"""

import argparse
from dataclasses import dataclass
import re
import sys
from typing import Optional

from log_analyzer import ERROR_ENTRY, IPV4, LEVEL, STATUS, TIMESTAMP


@dataclass(frozen=True)
class TestCase:
    input_text: str
    expected_valid: bool


@dataclass(frozen=True)
class RegexSuite:
    id: int
    name: str
    pattern: str
    cases: list[TestCase]


SUITES: dict[int, RegexSuite] = {
    1: RegexSuite(
        id=1,
        name="Timestamp",
        pattern=TIMESTAMP,
        cases=[
            TestCase("2026-10-28 10:15:20", True),
            TestCase("2026-01-01 00:00:00", True),
            TestCase("2025-12-31 23:59:59", True),
            TestCase("2026-02-14 09:05:45", True),
            TestCase("2024-07-15 18:30:00", True),
            TestCase("2026-13-28 10:15:20", False),
            TestCase("2026-10-32 10:15:20", False),
            TestCase("2026-10-28 24:15:20", False),
            TestCase("2026/10/28 10:15:20", False),
            TestCase("2026-10-28 10:15", False),
        ],
    ),
    2: RegexSuite(
        id=2,
        name="IPv4 address",
        pattern=IPV4,
        cases=[
            TestCase("192.168.1.10", True),
            TestCase("10.0.0.8", True),
            TestCase("255.255.255.255", True),
            TestCase("0.0.0.0", True),
            TestCase("172.16.254.1", True),
            TestCase("256.1.1.1", False),
            TestCase("192.168.1", False),
            TestCase("192.168.1.10.5", False),
            TestCase("192.168.01.1", False),
            TestCase("192.168.1.abc", False),
        ],
    ),
    3: RegexSuite(
        id=3,
        name="Log level",
        pattern=LEVEL,
        cases=[
            TestCase("INFO", True),
            TestCase("WARNING", True),
            TestCase("ERROR", True),
            TestCase("DEBUG", True),
            TestCase("CRITICAL", True),
            TestCase("error", False),
            TestCase("ERRORS", False),
            TestCase("WARN", False),
            TestCase("FATAL", False),
            TestCase("ERR0R", False),
        ],
    ),
    4: RegexSuite(
        id=4,
        name="HTTP status code",
        pattern=STATUS,
        cases=[
            TestCase("200", True),
            TestCase("404", True),
            TestCase("500", True),
            TestCase("301", True),
            TestCase("503", True),
            TestCase("99", False),
            TestCase("600", False),
            TestCase("2000", False),
            TestCase("4O4", False),
            TestCase("000", False),
        ],
    ),
    5: RegexSuite(
        id=5,
        name="Error log entry",
        pattern=ERROR_ENTRY,
        cases=[
            TestCase("2026-10-28 10:16:05 ERROR 404 192.168.1.15", True),
            TestCase("2026-10-28 10:17:42 ERROR 500 10.0.0.8", True),
            TestCase("2026-10-28 11:02:19 ERROR 503 172.16.0.4", True),
            TestCase("2026-10-29 00:00:01 ERROR 403 203.0.113.77", True),
            TestCase("2026-11-02 23:59:59 ERROR 502 192.168.10.200", True),
            TestCase("2026-10-28 10:15:20 INFO 200 192.168.1.10", False),
            TestCase("2026-10-28 10:16:05 error 404 192.168.1.15", False),
            TestCase("2026-10-28 10:16:05 ERRORS 404 192.168.1.15", False),
            TestCase("2026-10-28 10:16:05 ERROR 404 192.168.1.256", False),
            TestCase("ERROR 404 192.168.1.15", False),
        ],
    ),
}


def run_tests(selected_id: Optional[int] = None) -> bool:
    """Execute test cases and print a structured report."""
    suites_to_run = (
        [SUITES[selected_id]] if selected_id in SUITES else list(SUITES.values())
    )

    total_count = 0
    passed_count = 0

    for suite in suites_to_run:
        print(f"\nRegex {suite.id}: {suite.name}")
        print("-" * 78)
        print(f"{'No.':<4}{'Input string':<46}{'Expected':<10}{'Actual':<9}{'Result'}")

        for index, test in enumerate(suite.cases, start=1):
            is_match = re.fullmatch(suite.pattern, test.input_text) is not None
            is_passed = is_match == test.expected_valid

            total_count += 1
            if is_passed:
                passed_count += 1

            expected_label = "Valid" if test.expected_valid else "Invalid"
            actual_label = "Valid" if is_match else "Invalid"
            result_label = "PASS" if is_passed else "FAIL"

            print(
                f"{index:<4}{test.input_text:<46}{expected_label:<10}"
                f"{actual_label:<9}{result_label}"
            )

    print(f"\nTotal: {passed_count}/{total_count} test cases passed")
    return passed_count == total_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run test suite for log analysis regular expressions"
    )
    parser.add_argument(
        "suite_id",
        type=int,
        nargs="?",
        choices=[1, 2, 3, 4, 5],
        help="Optional regex ID (1 to 5) to test individually",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    all_passed = run_tests(args.suite_id)
    sys.exit(0 if all_passed else 1)
