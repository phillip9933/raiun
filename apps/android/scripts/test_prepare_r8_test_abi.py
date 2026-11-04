import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("prepare_r8_test_abi.py")
SPEC = importlib.util.spec_from_file_location("prepare_r8_test_abi", SCRIPT)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class AbiInventoryChecks(unittest.TestCase):
    def test_identical_runtime_duplicates_canonicalize_and_conflicting_variant_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            one, one_copy, two, conflict = (root / name for name in ("one.aar", "one-copy.aar", "two.jar", "conflict.aar"))
            one.write_bytes(b"artifact-one")
            one_copy.write_bytes(b"artifact-one")
            two.write_bytes(b"artifact-two")
            conflict.write_bytes(b"artifact-one-different")
            pins = {"g:one:1": TOOL.sha_file(one), "g:two:2": TOOL.sha_file(two),
                    "g:unused:9": "f" * 64}
            runtime = [
                {"component": "g:one:1", "path": str(one)},
                {"component": "g:one:1", "path": str(one_copy)},
                {"component": "g:two:2", "path": str(two)},
            ]
            canonical, duplicates, unused = TOOL.validate_runtime_inventory(runtime, pins)
            self.assertEqual(2, len(canonical))
            self.assertEqual([{"component": "g:one:1", "sha256": pins["g:one:1"],
                               "paths": [str(one.resolve()), str(one_copy.resolve())]}], duplicates)
            self.assertEqual(["g:unused:9"], unused)
            with self.assertRaisesRegex(ValueError, "Pinned runtime artifact hash mismatch"):
                TOOL.validate_runtime_inventory(runtime + [{"component": "g:one:1", "path": str(conflict)}], pins)
            with self.assertRaisesRegex(ValueError, "absent from canonical pins"):
                TOOL.validate_runtime_inventory(runtime + [{"component": "g:extra:1", "path": str(one)}], pins)
            with self.assertRaisesRegex(ValueError, "coordinate/hash multisets differ"):
                TOOL.validate_variant_runtime_equality(runtime, [runtime[0]], pins)

    def test_duplicate_class_must_be_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first.jar", Path(directory) / "second.jar"
            for jar, payload in ((first, b"one"), (second, b"two")):
                with zipfile.ZipFile(jar, "w") as archive:
                    archive.writestr("sample/Type.class", payload)
            classes = {role: {} for role in ("target", "source", "library")}
            owners = {role: {} for role in classes}
            TOOL.read_classes_from_jar(first, "target", classes, owners, [])
            with self.assertRaisesRegex(ValueError, "Conflicting target class"):
                TOOL.read_classes_from_jar(second, "target", classes, owners, [])

    def test_missing_real_target_diagnostic_is_fatal(self):
        self.assertTrue(TOOL.missing_target_diagnostics([
            "Missing method void eu.opencloud.android.next.Store.open()",
            "Missing class org.opencv.core.CvException",
        ]))
        self.assertEqual([], TOOL.missing_target_diagnostics([
            "Missing class java.beans.Introspector",
            "Missing class com.google.errorprone.annotations.MustBeClosed",
            "Missing class java.lang.invoke.StringConcatFactory (referenced from: void eu.opencloud.android.next.AppUpdateInstallJourneyAndroidTest.run())",
        ]))
        java_concat = "Missing class java.lang.invoke.StringConcatFactory (referenced from: void eu.opencloud.android.next.AppUpdateInstallJourneyAndroidTest.run())"
        self.assertEqual("jvm_or_compiler_runtime", TOOL.classify_missing_diagnostic(java_concat))
        true_missing = "Missing method void eu.opencloud.android.next.Store.open() (referenced from: void test())"
        self.assertEqual([true_missing], TOOL.missing_target_diagnostics([true_missing]))
        self.assertEqual("hidden_android_api", TOOL.classify_missing_diagnostic(
            "Missing method android.app.Activity androidx.test.internal.runner.hidden.ExposedInstrumentationApi.execStartActivity()"))
        self.assertIsNone(TOOL.classify_missing_diagnostic("Missing class com.example.Unknown"))

    def test_rule_count_is_dynamic_but_requires_critical_abi_and_no_wildcards(self):
        valid = """-keep class okhttp3.OkHttpClient$Builder {
  public okhttp3.OkHttpClient$Builder addInterceptor(okhttp3.Interceptor);
}
-keep class eu.opencloud.android.next.ui.EncryptedPdfDocument {
  public boolean isBackingCleared$app_r8Validation();
}
"""
        self.assertEqual(2, TOOL.validate_rule_inventory(valid))
        with self.assertRaisesRegex(ValueError, "no test-to-target roots"):
            TOOL.validate_rule_inventory("")
        with self.assertRaisesRegex(ValueError, "Wildcard"):
            TOOL.validate_rule_inventory(valid + "-keep class ** { *; }\n")


if __name__ == "__main__":
    unittest.main()
