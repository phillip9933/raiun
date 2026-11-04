import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("run_r8_native_checks.py")
SPEC = importlib.util.spec_from_file_location("run_r8_native_checks", SCRIPT)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class InstrumentationOutputChecks(unittest.TestCase):
    def test_success_counts_from_runner_stream(self):
        output = """INSTRUMENTATION_STATUS: numtests=2
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: -3
INSTRUMENTATION_RESULT: stream=OK (2 tests)
INSTRUMENTATION_CODE: -1
"""
        self.assertEqual({"tests": 2, "passed": 1, "failures": 0, "skipped": 1, "complete": True,
                          "instrumentation_status_codes": 2}, TOOL.parse_instrumentation(output))

    def test_failure_and_error_statuses_are_counted(self):
        output = """INSTRUMENTATION_STATUS: numtests=3
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: -2
INSTRUMENTATION_STATUS_CODE: -1
INSTRUMENTATION_RESULT: stream=FAILURES!!!\nTests run: 3, Failures: 1, Errors: 1
"""
        self.assertEqual(2, TOOL.parse_instrumentation(output)["failures"])

    def test_unknown_or_empty_result_has_no_fabricated_count(self):
        self.assertEqual(0, TOOL.parse_instrumentation("runner started")["tests"])

    def test_partial_or_nonraw_output_cannot_claim_complete_suite(self):
        partial = "INSTRUMENTATION_STATUS: numtests=2\nINSTRUMENTATION_STATUS_CODE: 0\nINSTRUMENTATION_CODE: 0\n"
        self.assertFalse(TOOL.parse_instrumentation(partial)["complete"])
        nonraw = "INSTRUMENTATION_RESULT: stream=OK (2 tests)\nINSTRUMENTATION_CODE: -1\n"
        self.assertFalse(TOOL.parse_instrumentation(nonraw)["complete"])


if __name__ == "__main__":
    unittest.main()
