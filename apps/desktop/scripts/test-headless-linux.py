#!/usr/bin/env python3
"""Synthetic install and disconnected headless IPC checks; never signs in or mounts."""
import argparse
import hashlib
import json
import os
import signal
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def test_checksums_and_existing_install_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix="raiun-headless-install-") as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            shutil.copyfile(ROOT / "packaging/headless-linux/install.sh", bundle / "install.sh")
            for name in ("raiun", "raiun-agent"):
                (bundle / name).write_bytes(b"synthetic executable\n")
            for name in ("README.md", "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md", "PRIVACY.md"):
                (bundle / name).write_text("synthetic document\n")
            (bundle / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256((bundle / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ("raiun", "raiun-agent")))
            destination = root / "new install with spaces"
            command = ["bash", str(bundle / "install.sh"), "--prefix", str(destination)]
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual((destination / "raiun").read_bytes(), b"synthetic executable\n")
            self.assertEqual((destination / "raiun").stat().st_mode & 0o777, 0o755)
            (destination / "raiun").write_bytes(b"preserved local file")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual((destination / "raiun").read_bytes(), b"preserved local file")
            (bundle / "raiun-agent").write_bytes(b"corrupted")
            second = root / "second"
            result = subprocess.run(command[:-1] + [str(second)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(second.exists())


def smoke(binaries):
    """Run only disconnected metadata/configuration and guarded refusals."""
    cli = binaries / "raiun"
    agent = binaries / "raiun-agent"
    with tempfile.TemporaryDirectory(prefix="raiun-headless-smoke-") as temporary:
        root = Path(temporary)
        state = root / "state"
        helpers = root / "helpers"
        helpers.mkdir()
        marker = root / "keyring-called"
        helper = helpers / "secret-tool"
        helper.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
        helper.chmod(0o700)
        environment = dict(os.environ, HOME=str(root), RAIUN_STATE_DIR=str(state),
                           DISPLAY="", WAYLAND_DISPLAY="", DBUS_SESSION_BUS_ADDRESS="",
                           PATH=str(helpers) + os.pathsep + os.environ.get("PATH", ""))
        environment.pop("RAIUN_HEADLESS_CONFIG", None)
        with (root / "agent.log").open("wb") as log:
            process = subprocess.Popen([str(cli), "drive", "serve"], env=environment,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)

            def drive(*arguments, success=True):
                result = subprocess.run([str(cli), "drive", "--json", *arguments],
                                        env=environment, capture_output=True, timeout=15)
                assert (result.returncode == 0) == success, result.stderr.decode()
                return json.loads(result.stdout) if success else result

            try:
                deadline = time.monotonic() + 15
                while not (state / "control.sock").exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert process.poll() is None and (state / "control.sock").exists(), "Headless agent did not start"
                status = drive("status")
                assert status["runtime_mode"] == "mount_only"
                assert status["credential_storage"] == "memory_only"
                assert status["folder_sync_enabled"] is False
                assert status["connected"] is False and status["mounted"] is False
                assert status["cloud_root"] == str(root / "RaiunHeadless")
                drive("spaces", success=False)
                added = drive("accounts", "add", "--label", "Synthetic second", "--path", str(root / "second"))
                status = drive("status", "--profile", added["id"])
                assert status["profile_id"] == added["id"] and status["runtime_mode"] == "mount_only"
                assert status["credential_storage"] == "memory_only"
                for action in ("sync_now", "pair_add", "set_autostart", "vault_unlock"):
                    result = subprocess.run([str(agent), "request", json.dumps({"action": action})],
                                            env=environment, capture_output=True, timeout=15)
                    if action == "vault_unlock":
                        # The command-line secret guard refuses this before IPC.
                        assert result.returncode != 0 and not result.stdout
                    else:
                        assert result.returncode == 0
                        assert json.loads(result.stdout)["ok"] is False
                drive("logout")
                drive("stop")
                process.wait(timeout=15)
                assert process.returncode == 0
                assert not marker.exists(), "Headless mode unexpectedly invoked Secret Service"
                assert not (state / "control.sock").exists(), "Socket not removed on shutdown"
            finally:
                if process.poll() is None:
                    # The CLI foreground launcher waits for its agent. Request shutdown
                    # first so a test interruption cannot orphan the child.
                    try:
                        subprocess.run([str(agent), "request", '{"action":"shutdown"}'],
                                       env=environment, capture_output=True, timeout=15)
                        process.wait(timeout=15)
                    except (subprocess.TimeoutExpired, OSError):
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)
    print("Disconnected headless CLI/agent smoke passed (no display, keyring, sign-in, or mount)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(InstallTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.binaries:
        smoke(args.binaries)
