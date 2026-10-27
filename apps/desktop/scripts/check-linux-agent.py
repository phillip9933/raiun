#!/usr/bin/env python3
"""Reject stale Linux payloads using isolated, disconnected synthetic state."""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def check(agent):
    with tempfile.TemporaryDirectory(prefix="raiun-agent-payload-check-") as temporary:
        root = Path(temporary)
        environment = dict(os.environ, RAIUN_STATE_DIR=str(root / "state"))
        with (root / "agent.log").open("wb") as log:
            process = subprocess.Popen([str(agent), "serve"], env=environment,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            endpoint = root / "state/control.sock"

            def request(message):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(5)
                    connection.connect(str(endpoint))
                    pid, uid, _ = struct.unpack("3i", connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    assert pid == process.pid and uid == os.getuid(), "Unexpected agent peer"
                    connection.sendall(json.dumps(message).encode() + b"\n")
                    response = b""
                    while b"\n" not in response:
                        chunk = connection.recv(65536)
                        assert chunk and len(response) + len(chunk) <= 1048576, "Invalid agent reply"
                        response += chunk
                    return json.loads(response.split(b"\n", 1)[0])

            try:
                deadline = time.monotonic() + 15
                while not endpoint.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert process.poll() is None and endpoint.exists(), "Synthetic agent did not start"
                status = request({"action": "status"})
                assert status.get("ok") is True, "Synthetic status failed"
                assert status["data"].get("folder_settings_supported") is True, "Stale agent: folder editing unsupported"
                # No generation, real pair ID or policy is supplied: this must reject
                # before any mutation, while proving that the dispatch exists.
                result = request({"action": "pair_update", "id": "invalid-payload-probe"})
                assert result.get("ok") is False, "Incomplete update was unexpectedly accepted"
                assert result.get("error") == "expected_auth_generation must be an unsigned integer", "Stale or incompatible folder update dispatch"
                assert request({"action": "shutdown"}).get("ok") is True, "Synthetic shutdown failed"
                process.wait(timeout=15)
                assert process.returncode == 0, "Synthetic agent did not exit normally"
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
    print("Linux agent payload check passed: folder editing capability and dispatch verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=lambda value: Path(value).resolve(strict=True))
    check(parser.parse_args().agent)
