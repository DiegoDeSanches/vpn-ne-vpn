#!/usr/bin/env python3
"""Run OnionRoute QA suites and emit JSON plus JUnit without raw traffic data."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
import time
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

SUITES = {
    "integration": TESTS / "integration",
    "leak": TESTS / "leak-tests",
    "chaos": TESTS / "chaos",
    "protocol": TESTS / "protocol-conformance",
    "performance": TESTS / "performance",
    "privacy": TESTS / "security",
    "release": TESTS / "release",
    "environment": TESTS / "environments",
    "staging": TESTS / "staging",
    "compatibility": TESTS / "compatibility",
}


class PrivacySafeResult(unittest.TestResult):
    def __init__(self) -> None:
        super().__init__()
        self.started: dict[str, float] = {}
        self.records: list[dict[str, object]] = []

    def startTest(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        super().startTest(test)
        self.started[test.id()] = time.monotonic()

    def _record(self, test: unittest.case.TestCase, status: str, error_type: str | None = None) -> None:
        duration = (time.monotonic() - self.started.pop(test.id(), time.monotonic())) * 1000.0
        record: dict[str, object] = {
            "test": test.id(),
            "status": status,
            "duration_ms": round(duration, 3),
        }
        if error_type:
            record["error_type"] = error_type
        self.records.append(record)
        print(f"{status.upper():5} {test.id()} ({duration:.1f} ms)")

    def addSuccess(self, test: unittest.case.TestCase) -> None:  # noqa: N802
        super().addSuccess(test)
        self._record(test, "pass")

    def addFailure(self, test: unittest.case.TestCase, err: tuple[type[BaseException], BaseException, object]) -> None:  # noqa: N802
        super().addFailure(test, err)
        self._record(test, "fail", err[0].__name__)

    def addError(self, test: unittest.case.TestCase, err: tuple[type[BaseException], BaseException, object]) -> None:  # noqa: N802
        super().addError(test, err)
        self._record(test, "error", err[0].__name__)

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:  # noqa: N802
        super().addSkip(test, reason)
        self._record(test, "skip")


def load_suite(names: list[str]) -> unittest.TestSuite:
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for suite_name in names:
        directory = SUITES[suite_name]
        for index, path in enumerate(sorted(directory.glob("test_*.py"))):
            module_name = f"orqa_{suite_name}_{index}_{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"cannot load test module: {path}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            suite.addTests(loader.loadTestsFromModule(module))
    return suite


def write_reports(result: PrivacySafeResult, output: pathlib.Path, selected: list[str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    summary = {
        "schema_version": 1,
        "suite": "onionroute-qa",
        "selected": selected,
        "passed": result.wasSuccessful(),
        "counts": {
            "run": result.testsRun,
            "failed": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
        },
        "results": result.records,
    }
    (output / "qa-report.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    root = ET.Element(
        "testsuite",
        name="onionroute-qa",
        tests=str(result.testsRun),
        failures=str(len(result.failures)),
        errors=str(len(result.errors)),
        skipped=str(len(result.skipped)),
    )
    for record in result.records:
        case = ET.SubElement(
            root,
            "testcase",
            name=str(record["test"]),
            time=f"{float(record['duration_ms']) / 1000.0:.6f}",
        )
        if record["status"] == "fail":
            ET.SubElement(case, "failure", message=str(record.get("error_type", "failure")))
        elif record["status"] == "error":
            ET.SubElement(case, "error", message=str(record.get("error_type", "error")))
        elif record["status"] == "skip":
            ET.SubElement(case, "skipped")
    ET.ElementTree(root).write(output / "qa-junit.xml", encoding="utf-8", xml_declaration=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", action="append", choices=("all", *SUITES), default=[])
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "test-results")
    arguments = parser.parse_args()
    requested = arguments.suite or ["all"]
    selected = list(SUITES) if "all" in requested else list(dict.fromkeys(requested))
    result = PrivacySafeResult()
    load_suite(selected).run(result)
    write_reports(result, arguments.output, selected)
    print(
        f"SUMMARY run={result.testsRun} failures={len(result.failures)} "
        f"errors={len(result.errors)} skipped={len(result.skipped)}"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
