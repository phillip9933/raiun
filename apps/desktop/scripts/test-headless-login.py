#!/usr/bin/env python3
"""Synthetic headless app-token lifecycle; no real server, FUSE or autostart."""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time


def run(binaries):
    token = "synthetic-cli-app-token"
    authorization = "Basic " + base64.b64encode(f"fixture-user:{token}".encode()).decode()
    requests = []
    identity_allowed = True

    class Server(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self):
            requests.append((self.command, self.path))
            body_length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(body_length)
            if self.headers.get("Authorization") != authorization:
                status, body = 401, b"unauthorized"
            elif self.path == "/graph/v1.0/me" and not identity_allowed:
                status, body = 401, b"synthetic identity rejection"
            elif self.path == "/graph/v1.0/me":
                status, body = 200, b'{"id":"fixture-user"}'
            elif self.path == "/graph/v1.0/me/drives":
                status, body = 200, json.dumps({"value": [
                    {"id": "personal", "name": "Personal", "driveType": "personal",
                     "root": {"id": "personal-root", "webDavUrl": origin + "/dav/spaces/personal/"}},
                    {"id": "project", "name": "Projects", "driveType": "project",
                     "root": {"id": "project-root", "webDavUrl": origin + "/dav/spaces/project/"}}
                ]}).encode()
            elif self.command == "PROPFIND" and self.path == "/dav/spaces/personal/":
                status, body = 207, b'''<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:response><d:href>/dav/spaces/personal/</d:href><d:propstat><d:prop>
<d:resourcetype><d:collection/></d:resourcetype><oc:fileid>personal-root</oc:fileid>
<d:getetag>"root-v1"</d:getetag><d:getcontentlength>0</d:getcontentlength>
</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>'''
            else:
                status, body = 404, b"unexpected synthetic request"
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json" if status == 200 else "application/xml")
            self.end_headers()
            self.wfile.write(body)

        do_GET = respond
        do_PROPFIND = respond
        do_POST = respond

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Server)
    origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="raiun-headless-login-") as temporary:
            root = Path(temporary)
            state = root / "state"
            config_path = root / "headless.json"
            config = {"schema_version": 1, "server": origin, "auth": "app_token",
                      "username": "fixture-user", "mount_path": str(root / "drive"),
                      "auto_mount": False, "remember_login": True,
                      "reconnect_interval_seconds": 1, "profile": "default"}
            config_path.write_text(json.dumps(config))
            environment = dict(os.environ, HOME=str(root), RAIUN_STATE_DIR=str(state),
                               RAIUN_HEADLESS_CONFIG=str(config_path), DISPLAY="",
                               WAYLAND_DISPLAY="", DBUS_SESSION_BUS_ADDRESS="")
            process, log, log_number = None, None, 0
            transcripts = []

            def cli(*args, input_bytes=None, success=True):
                result = subprocess.run([str(binaries / "raiun"), "--config", str(config_path),
                                         "drive", "--json", *args], env=environment,
                                        input=input_bytes, capture_output=True, timeout=30)
                transcripts.extend((result.stdout, result.stderr))
                assert (result.returncode == 0) == success, result.stderr.decode()
                return json.loads(result.stdout) if success else result

            def start():
                nonlocal process, log, log_number
                log_number += 1
                log = (root / f"agent-{log_number}.log").open("wb")
                process = subprocess.Popen([str(binaries / "raiun"), "--config", str(config_path),
                                            "drive", "serve"], env=environment,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise AssertionError("Synthetic headless agent exited early")
                    if (state / "control.sock").exists():
                        return
                    time.sleep(0.05)
                raise AssertionError("Synthetic agent did not start")

            def wait_status(predicate):
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    status = cli("status")
                    if predicate(status):
                        return status
                    time.sleep(0.05)
                raise AssertionError("Expected synthetic connection state was not reached")

            def stop():
                nonlocal process
                if process is not None and process.poll() is None:
                    cli("stop")
                    process.wait(timeout=15)
                    assert process.returncode == 0
                if log is not None:
                    log.close()
                process = None

            try:
                start()
                wait_status(lambda s: not s["restoring"])
                cli("login", "--app-token", "--token-stdin", input_bytes=(token + "\n").encode())
                status = wait_status(lambda s: s["connected"])
                assert status["credential_storage"] == "private_file"
                assert status["mounted"] is False and status["folder_sync_enabled"] is False
                assert len(cli("spaces")) == 2
                credential_file = state / "sessions/default.json"
                assert token in credential_file.read_text()
                assert token not in config_path.read_text()
                assert credential_file.stat().st_mode & 0o777 == 0o600
                stop()
                # Retained namespace/drives remain readable, but fixed /me
                # refuses the token. Restore must not promote it online.
                identity_allowed = False
                start()
                status = wait_status(lambda s: not s["restoring"])
                assert not status["connected"] and status["error"]
                assert credential_file.exists()
                stop()
                identity_allowed = True
                start()
                wait_status(lambda s: s["connected"] and not s["restoring"])
                stop()
                config["username"] = "different-user"
                config_path.write_text(json.dumps(config))
                start()
                status = wait_status(lambda s: not s["restoring"])
                assert not status["connected"] and status["error"]
                assert credential_file.exists(), "Mismatch must preserve recovery credentials"
                stop()
                config["username"] = "fixture-user"
                config_path.write_text(json.dumps(config))
                start()
                wait_status(lambda s: s["connected"])
                cli("logout")
                assert not credential_file.exists()
                stop()
                start()
                status = wait_status(lambda s: not s["restoring"])
                assert not status["connected"]
                cli("login", "--app-token", "--token-stdin", input_bytes=b"synthetic-wrong-token\n", success=False)
                assert not credential_file.exists()
                assert not cli("status")["connected"]
                stop()
                # Explicit logout must delete older remembered credentials
                # even after remember_login is disabled for the next process.
                start()
                wait_status(lambda s: not s["restoring"])
                cli("login", "--app-token", "--token-stdin", input_bytes=(token + "\n").encode())
                assert credential_file.exists()
                stop()
                config["remember_login"] = False
                config_path.write_text(json.dumps(config))
                start()
                status = wait_status(lambda s: not s["restoring"])
                assert not status["connected"] and status["credential_storage"] == "memory_only"
                assert credential_file.exists(), "Disabling persistence alone must preserve the prior blob"
                cli("logout")
                assert not credential_file.exists(), "Explicit logout must revoke old saved credentials"
                stop()
                config["remember_login"] = True
                config_path.write_text(json.dumps(config))
                start()
                status = wait_status(lambda s: not s["restoring"])
                assert not status["connected"]
                stop()
                assert all(method in ("GET", "PROPFIND") for method, _ in requests)
                encoded = authorization.removeprefix("Basic ").encode()
                for data in transcripts + [p.read_bytes() for p in root.glob("agent-*.log")]:
                    assert token.encode() not in data and encoded not in data
            finally:
                if process is not None and process.poll() is None:
                    try:
                        stop()
                    finally:
                        if process is not None and process.poll() is None:
                            process.terminate()
                            process.wait(timeout=15)
                if log is not None:
                    log.close()
        print(json.dumps({"app_token_login": "pass", "private_persistence": "pass",
                          "restart_restore": "pass", "config_identity_binding": "pass",
                          "restore_revalidates_fixed_identity": "pass",
                          "logout_survives_restart": "pass", "logout_after_disabling_persistence": "pass", "rejected_token": "pass",
                          "no_oauth_exchange": "pass", "secret_output_redaction": "pass",
                          "mounts_or_autostart": "not_executed"}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", required=True, type=Path)
    run(parser.parse_args().binaries.resolve())
