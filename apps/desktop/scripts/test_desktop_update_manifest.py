from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import desktop_update_manifest as manifest

TAG = "desktop-v0.7.0-beta.1-test.2"


class ManifestHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="raiun-manifest-test-")
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.linux = self.inputs / "raiun-test-linux.AppImage"
        self.linux.write_bytes(b"synthetic-linux-package\x00payload")
        self.linux_sig = self.inputs / "linux.sig"
        self.linux_sig.write_text("TEST-LINUX-SIGNATURE\n", encoding="utf-8")
        self.windows = self.inputs / "raiun-test-windows.nsis.zip"
        self.windows.write_bytes(b"synthetic-windows-nsis-updater-zip")
        self.windows_sig = self.inputs / "windows.sig"
        self.windows_sig.write_text("TEST-WINDOWS-SIGNATURE\n", encoding="utf-8")
        self.notes = self.inputs / "notes.txt"
        self.notes.write_text("Synthetic preview\nSecond line\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build(self, **overrides: str | None) -> tuple[bytes, bytes]:
        options = {
            "tag": TAG,
            "linux_package": str(self.linux),
            "linux_signature": str(self.linux_sig),
            "windows_package": str(self.windows),
            "windows_signature": str(self.windows_sig),
            "notes_file": str(self.notes),
        }
        options.update(overrides)
        return manifest.build_documents(**options)

    def test_positive_is_deterministic_and_binds_exact_artifacts(self) -> None:
        first_manifest, first_inventory = self.build()
        second_manifest, second_inventory = self.build()
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_inventory, second_inventory)
        parsed = json.loads(first_manifest)
        self.assertEqual(parsed["version"], TAG.removeprefix("desktop-v"))
        self.assertEqual(parsed["notes"], "Synthetic preview\nSecond line")
        linux = parsed["platforms"]["linux-x86_64-appimage"]
        windows = parsed["platforms"]["windows-x86_64-nsis"]
        self.assertEqual(
            linux["url"],
            f"https://github.com/phillip9933/raiun/releases/download/{TAG}/{self.linux.name}",
        )
        self.assertEqual(linux["signature"], "TEST-LINUX-SIGNATURE")
        self.assertTrue(windows["url"].endswith(f"/{self.windows.name}"))
        inventory = json.loads(first_inventory)
        self.assertEqual(inventory["repository"], "phillip9933/raiun")
        self.assertEqual(inventory["tag"], TAG)
        self.assertEqual(inventory["manifest"]["sha256"], hashlib.sha256(first_manifest).hexdigest())
        self.assertEqual(inventory["artifacts"][0]["package"]["sha256"], hashlib.sha256(self.linux.read_bytes()).hexdigest())
        self.assertEqual(inventory["artifacts"][1]["package"]["sha256"], hashlib.sha256(self.windows.read_bytes()).hexdigest())
        self.assertEqual(inventory["cryptographicSignatureVerification"], "not performed by this helper")

    def test_rejects_non_desktop_non_semver_and_noncanonical_tag(self) -> None:
        for bad in (
            "android-v1.2.3",
            "desktop-v1.02.3",
            "desktop-v1.2.3-01",
            "desktop-v1.2",
            "desktop-v1.2.3/evil",
        ):
            with self.subTest(tag=bad), self.assertRaises(manifest.InputError):
                self.build(tag=bad)
        too_long = "desktop-v0.7.0-" + "a" * 100
        with self.assertRaisesRegex(manifest.InputError, "96-byte"):
            self.build(tag=too_long)

    def test_rejects_wrong_suffix_and_duplicate_input(self) -> None:
        bad = self.inputs / "not-an-appimage.zip"
        bad.write_bytes(b"package")
        with self.assertRaisesRegex(manifest.InputError, r"ending in \.AppImage"):
            self.build(linux_package=str(bad))
        with self.assertRaisesRegex(manifest.InputError, "inputs must be distinct"):
            self.build(windows_signature=str(self.linux_sig))

    def test_rejects_global_asset_basename_collisions(self) -> None:
        other_dir = self.inputs / "other"
        other_dir.mkdir()
        duplicate_signature = other_dir / self.linux_sig.name
        duplicate_signature.write_text("OTHER-SIGNATURE", encoding="utf-8")
        with self.assertRaisesRegex(manifest.InputError, "basenames must be globally unique"):
            self.build(windows_signature=str(duplicate_signature))

    def test_rejects_hard_link_aliases(self) -> None:
        alias = self.inputs / "alias.nsis.zip"
        os.link(self.linux, alias)
        with self.assertRaisesRegex(manifest.InputError, "hard-link aliases"):
            self.build(windows_package=str(alias))

    def test_rejects_symlink_and_nonregular_input(self) -> None:
        link = self.inputs / "link.AppImage"
        link.symlink_to(self.linux)
        with self.assertRaisesRegex(manifest.InputError, "symlink"):
            self.build(linux_package=str(link))
        with self.assertRaisesRegex(manifest.InputError, "regular file"):
            self.build(windows_package=str(self.inputs))

    def test_rejects_missing_empty_and_oversized_signature(self) -> None:
        missing = self.inputs / "missing.sig"
        with self.assertRaisesRegex(manifest.InputError, "does not exist"):
            self.build(windows_signature=str(missing))
        self.windows_sig.write_bytes(b"\n")
        with self.assertRaisesRegex(manifest.InputError, "one non-empty printable line"):
            self.build()
        self.windows_sig.write_bytes(b"12345")
        with mock.patch.object(manifest, "MAX_SIGNATURE_BYTES", 4):
            with self.assertRaisesRegex(manifest.InputError, "larger than 4 bytes"):
                self.build()

    def test_rejects_oversized_package(self) -> None:
        with mock.patch.object(manifest, "MAX_PACKAGE_BYTES", 3):
            with self.assertRaisesRegex(manifest.InputError, "larger than 3 bytes"):
                self.build()

    def test_outputs_are_exclusive_and_cli_emits_parseable_json(self) -> None:
        manifest_out = self.root / "desktop-update.json"
        inventory_out = self.root / "inventory.json"
        args = argparse.Namespace(
            tag=TAG,
            linux_package=str(self.linux),
            linux_signature=str(self.linux_sig),
            windows_package=str(self.windows),
            windows_signature=str(self.windows_sig),
            notes_file=str(self.notes),
            manifest_out=str(manifest_out),
            inventory_out=str(inventory_out),
        )
        created_manifest, created_inventory = manifest.run(args)
        self.assertEqual(created_manifest, manifest_out)
        self.assertEqual(created_inventory, inventory_out)
        self.assertEqual(json.loads(manifest_out.read_text())["version"], TAG.removeprefix("desktop-v"))
        with self.assertRaisesRegex(manifest.InputError, "refusing to replace"):
            manifest.run(args)
        self.assertEqual(manifest_out.stat().st_mode & 0o777, 0o600)
        self.assertEqual(inventory_out.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
