import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("archive_r8_artifacts.py")
SPEC = importlib.util.spec_from_file_location("archive_r8_artifacts", SCRIPT)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class R8ArchiveChecks(unittest.TestCase):
    def test_archive_repeats_identically_and_refuses_different_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "unsigned.apk"
            mapping_dir = root / "mapping"
            mapping_dir.mkdir()
            archive_root = root / "archive"
            map_id = "a" * 64
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", f"synthetic r8-map-id-{map_id}".encode())
            for name in TOOL.REPORTS:
                content = f"synthetic {name}\n"
                if name == "mapping.txt":
                    content = f"# compiler: R8\n# pg_map_id: {map_id}\nSynthetic -> a:\n"
                (mapping_dir / name).write_text(content)

            first = TOOL.archive(apk, mapping_dir, archive_root, "1.2.3")
            before = {path.name: path.read_bytes() for path in first.iterdir()}
            second = TOOL.archive(apk, mapping_dir, archive_root, "1.2.3")
            self.assertEqual(first, second)
            self.assertEqual(before, {path.name: path.read_bytes() for path in second.iterdir()})

            (mapping_dir / "usage.txt").write_text("changed report\n")
            with self.assertRaisesRegex(FileExistsError, "refusing overwrite"):
                TOOL.archive(apk, mapping_dir, archive_root, "1.2.3")

    def test_stale_mapping_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = root / "unsigned.apk"
            mapping_dir = root / "mapping"
            mapping_dir.mkdir()
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"synthetic r8-map-id-" + b"b" * 64)
            for name in TOOL.REPORTS:
                (mapping_dir / name).write_text(
                    f"# pg_map_id: {'a' * 64}\n" if name == "mapping.txt" else f"synthetic {name}\n"
                )
            with self.assertRaisesRegex(ValueError, "may be stale"):
                TOOL.archive(apk, mapping_dir, root / "archive", "1.2.3")
            self.assertFalse((root / "archive").exists())


if __name__ == "__main__":
    unittest.main()
