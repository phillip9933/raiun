#!/usr/bin/env python3
"""Opt-in production Linux CLI/FUSE acceptance using a synthetic loopback account.

All evidence, state, mounted roots and credentials are retained. No startup
registration, real accounts, forced termination, lazy unmount or deletion.
--serve-only provides the same persistent loopback backend for later VM-only
startup acceptance; it does not activate startup or run Raiun.
"""
import argparse
import base64
import fcntl
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, unquote
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

TOKEN = "synthetic-linux-fuse-app-token"
USER = "synthetic-linux-fuse-user"
BASIC = base64.b64encode(f"{USER}:{TOKEN}".encode()).decode()
AUTHORIZATION = "Basic " + BASIC
PERSONAL = b"synthetic Personal ordinary FUSE read\n"
PROJECT = b"synthetic Projects ordinary FUSE read\n"
ORIGINAL = b"synthetic Projects writable baseline\n"
UPDATED = b"synthetic Projects verified ordinary write\n"
ROOTS = {"personal": "/dav/spaces/personal/", "project": "/dav/spaces/project/"}
FILES = {
    ROOTS["personal"] + "read.bin": PERSONAL,
    ROOTS["project"] + "read.bin": PROJECT,
    ROOTS["project"] + "write.bin": ORIGINAL,
}
WRITE_PATH = ROOTS["project"] + "write.bin"
MAX_BODY = 1024 * 1024
MAX_LOG = 2 * 1024 * 1024
STATE_FORMAT = "raiun-synthetic-fuse-server-v1"


class Failure(Exception):
    """Only fixed, nonsecret messages from this harness are recorded."""


def require(condition, message):
    if not condition:
        raise Failure(message)


def ordinary_absolute(path):
    path = Path(path)
    require(path.is_absolute(), "Harness paths must be absolute")
    require(not any(ord(character) < 32 for character in str(path)), "Harness paths must not contain control characters")
    require(".." not in path.parts, "Harness paths must not contain parent traversal")
    for member in (path, *path.parents):
        require(not member.is_symlink(), "Harness paths/ancestors must not be symlinks")
    return path


def write_json(path, value):
    path = ordinary_absolute(path)
    temporary = path.with_name(path.name + ".next")
    # Never follow a preexisting helper path. Only a fresh/owned state file is replaced.
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


class Backend:
    def __init__(self, state_path):
        self.path = ordinary_absolute(state_path)
        require(self.path.parent.is_dir(), "Server-state parent must already exist")
        self.lock = threading.RLock()
        self.ownership = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.ownership, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(self.ownership)
            raise Failure("Synthetic server state already has an active owner") from error
        if self.path.exists():
            require(self.path.stat().st_size < MAX_BODY, "Server state exceeds fixture bound")
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
            require(self.data.get("format") == STATE_FORMAT, "Refusing foreign server state")
            require(set(self.data.get("files", {})) == set(FILES), "Unexpected persisted fixture files")
            for name, entry in self.data["files"].items():
                content = base64.b64decode(entry["body"], validate=True)
                require(content in (FILES[name], UPDATED) if name == WRITE_PATH else content == FILES[name],
                        "Persisted fixture content does not match synthetic scope")
                require(entry["revision"] in (1, 2), "Unexpected persisted fixture revision")
        else:
            self.data = {
                "format": STATE_FORMAT,
                "files": {name: {"body": base64.b64encode(content).decode(), "revision": 1}
                          for name, content in FILES.items()},
                "counts": {}, "gets": {}, "ranges": {}, "requests": [],
                "writes": [], "server_failures": 0,
            }
            self.save()
        self.origin = None

    def save(self):
        with self.lock:
            write_json(self.path, self.data)

    def count(self, name):
        self.data["counts"][name] = self.data["counts"].get(name, 0) + 1

    def record(self, method, path, status, headers):
        # No raw authorization, query, request body, error message or secret is logged.
        record = {"method": method, "route": path if path in self.known_paths() else "<unknown>",
                  "status": status, "if_match_present": "If-Match" in headers,
                  "range_present": "Range" in headers}
        if len(self.data["requests"]) < 4096:
            self.data["requests"].append(record)
        else:
            self.count("request_log_overflow")
        self.save()

    @staticmethod
    def known_paths():
        return set(FILES) | set(ROOTS.values()) | {root.rstrip("/") for root in ROOTS.values()} | {
            "/graph/v1.0/me", "/graph/v1.0/me/drives"}

    @staticmethod
    def etag(path, revision):
        space = "personal" if path.startswith(ROOTS["personal"]) else "project"
        filename = path.rsplit("/", 1)[-1].replace(".", "-")
        return f'"{space}-{filename}-v{revision}"'

    def metadata(self, path):
        for space, root in ROOTS.items():
            if path.rstrip("/") == root.rstrip("/"):
                return space + "!root", f'"{space}-root-v1"', 0, True
        entry = self.data["files"].get(path)
        if entry is None:
            return None
        space = "personal" if path.startswith(ROOTS["personal"]) else "project"
        return space + "!" + path.rsplit("/", 1)[-1], self.etag(path, entry["revision"]), len(base64.b64decode(entry["body"])), False

    def dav_response(self, path):
        identity, etag, length, directory = self.metadata(path)
        resource = "<d:collection/>" if directory else ""
        name = path.rstrip("/").rsplit("/", 1)[-1]
        return (f"<d:response><d:href>{escape(self.origin + path)}</d:href><d:propstat><d:prop>"
                f"<d:resourcetype>{resource}</d:resourcetype><d:getetag>{escape(etag)}</d:getetag>"
                f"<d:getcontentlength>{length}</d:getcontentlength><oc:fileid>{escape(identity)}</oc:fileid>"
                f"<oc:name>{escape(name)}</oc:name><oc:permissions>RDNVW</oc:permissions>"
                "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")

    def response(self, method, target, headers, body):
        with self.lock:
            parsed = urlsplit(target)
            path = unquote(parsed.path)
            if parsed.query or parsed.fragment or "%" in path or ".." in path.split("/"):
                self.count("unknown_requests")
                return 400, {}, b"invalid fixture route"
            if headers.get("Authorization") != AUTHORIZATION:
                self.count("authentication_failures")
                return 401, {"WWW-Authenticate": 'Basic realm="synthetic-raiun-fixture"'}, b"unauthorized"
            if method in ("GET", "HEAD") and path == "/graph/v1.0/me":
                self.count("identity_gets")
                return 200, {"Content-Type": "application/json"}, json.dumps({"id": USER}).encode()
            if method in ("GET", "HEAD") and path == "/graph/v1.0/me/drives":
                self.count("drive_list_gets")
                value = [{"id": space, "name": "Personal" if space == "personal" else "Projects",
                          "driveType": "personal" if space == "personal" else "project",
                          "root": {"id": space + "!root", "webDavUrl": self.origin + root,
                                   "permissions": ["read", "write"]}}
                         for space, root in ROOTS.items()]
                return 200, {"Content-Type": "application/json"}, json.dumps({"value": value}).encode()
            metadata = self.metadata(path)
            if metadata is None:
                self.count("unknown_requests")
                return 404, {}, b"unknown fixture route"
            identity, etag, length, directory = metadata
            if method == "OPTIONS":
                return 200, {"DAV": "1", "Allow": "GET,HEAD,PROPFIND,OPTIONS,PUT"}, b""
            if method == "PROPFIND":
                depth = headers.get("Depth", "0")
                if depth not in ("0", "1"):
                    self.count("bad_depth")
                    return 403, {}, b"fixture permits depth 0 or 1 only"
                paths = [path]
                if directory:
                    canonical = next(root for root in ROOTS.values() if root.rstrip("/") == path.rstrip("/"))
                    paths = [canonical]
                    if depth == "1":
                        paths += sorted(name for name in FILES if name.startswith(canonical))
                self.count("propfind_depth_" + depth)
                xml = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
                       + "".join(self.dav_response(name) for name in paths) + "</d:multistatus>")
                return 207, {"Content-Type": "application/xml; charset=utf-8"}, xml.encode()
            if method in ("GET", "HEAD") and not directory:
                condition = headers.get("If-Match")
                if condition is not None and condition != etag:
                    self.count("conditional_read_failures")
                    return 412, {"ETag": etag}, b""
                content = base64.b64decode(self.data["files"][path]["body"])
                key = "gets" if method == "GET" else "heads"
                self.data.setdefault(key, {})[path] = self.data.get(key, {}).get(path, 0) + 1
                if path == WRITE_PATH and self.data["files"][path]["revision"] == 2:
                    self.count("updated_content_reads")
                response_headers = {"Content-Type": "application/octet-stream", "ETag": etag, "Accept-Ranges": "bytes"}
                byte_range = headers.get("Range")
                if byte_range:
                    try:
                        require(byte_range.startswith("bytes=") and "," not in byte_range, "bad range")
                        first, last = byte_range[6:].split("-", 1)
                        first = int(first)
                        last = int(last) if last else len(content) - 1
                        require(0 <= first <= last and first < len(content), "bad range")
                    except (Failure, ValueError):
                        self.count("bad_ranges")
                        return 416, {"Content-Range": f"bytes */{len(content)}"}, b""
                    last = min(last, len(content) - 1)
                    response_headers["Content-Range"] = f"bytes {first}-{last}/{len(content)}"
                    self.data["ranges"][path] = self.data["ranges"].get(path, 0) + 1
                    return 206, response_headers, content[first:last + 1]
                return 200, response_headers, content
            if method == "PUT" and path == WRITE_PATH:
                self.count("put_attempts")
                if headers.get("If-Match") != etag or headers.get("If-None-Match") is not None:
                    self.count("conditional_write_failures")
                    return 412, {"ETag": etag}, b""
                if body != UPDATED or self.data["files"][path]["revision"] != 1:
                    self.count("unexpected_put_content_or_repeat")
                    return 409, {}, b"unexpected synthetic write"
                root_condition = headers.get("If")
                if root_condition is not None and root_condition != f'<{self.origin + ROOTS["project"]}> (["project-root-v1"])':
                    self.count("root_condition_failures")
                    return 412, {}, b"root condition mismatch"
                self.data["files"][path] = {"body": base64.b64encode(body).decode(), "revision": 2}
                self.data["writes"].append({"if_match": etag, "new_etag": self.etag(path, 2),
                                            "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                                            "root_condition_present": root_condition is not None})
                self.count("successful_puts")
                return 204, {"ETag": self.etag(path, 2)}, b""
            self.count("unexpected_methods")
            return 405, {"Allow": "GET,HEAD,PROPFIND,OPTIONS"}, b"unsupported fixture operation"

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.data))

    def close(self):
        self.save()
        fcntl.flock(self.ownership, fcntl.LOCK_UN)
        os.close(self.ownership)


class Server(http.server.ThreadingHTTPServer):
    # Handler sockets have a 10-second timeout; join them before releasing the
    # persistent state lease, avoiding a late handler racing a server restart.
    daemon_threads = False
    block_on_close = True

    def __init__(self, backend, port):
        self.backend = backend
        super().__init__(("127.0.0.1", port), Handler)
        backend.origin = f"http://127.0.0.1:{self.server_port}"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def __getattr__(self, name):
        # Include unknown HTTP verbs in the same authenticated rejection/counters.
        if name.startswith("do_"):
            return self.handle_request
        raise AttributeError(name)

    def handle_request(self):
        backend = self.server.backend
        with backend.lock:
            backend.count("request_total")
            if self.command not in ("GET", "HEAD", "PROPFIND", "OPTIONS"):
                backend.count("all_mutation_attempts")
        try:
            if self.headers.get("Transfer-Encoding"):
                with backend.lock:
                    backend.count("invalid_framing")
                status, headers, body = 400, {}, b"fixture requires bounded Content-Length"
            else:
                length = int(self.headers.get("Content-Length", "0"))
                require(0 <= length <= MAX_BODY, "Request body exceeds fixture bound")
                data = self.rfile.read(length)
                require(len(data) == length, "Incomplete fixture request body")
                status, headers, body = backend.response(self.command, self.path, self.headers, data)
            with backend.lock:
                backend.record(self.command, unquote(urlsplit(self.path).path), status, self.headers)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            with backend.lock:
                backend.count("response_disconnects")
                backend.save()
        except Exception:
            # Never print arbitrary HTTP/header/body/exception material.
            with backend.lock:
                backend.data["server_failures"] += 1
                backend.save()
            self.close_connection = True
        finally:
            self.close_connection = True

    do_GET = handle_request
    do_HEAD = handle_request
    do_PROPFIND = handle_request
    do_OPTIONS = handle_request
    do_PUT = handle_request
    do_POST = handle_request
    do_DELETE = handle_request
    do_MOVE = handle_request
    do_MKCOL = handle_request
    do_COPY = handle_request
    do_PATCH = handle_request


WORKER = r'''
import json, os, sys, time
from pathlib import Path
root = Path(sys.argv[2])
mode = sys.argv[1]
expected_p = b"synthetic Personal ordinary FUSE read\n"
expected_s = b"synthetic Projects ordinary FUSE read\n"
original = b"synthetic Projects writable baseline\n"
updated = b"synthetic Projects verified ordinary write\n"
if mode == "read":
    assert sorted(os.listdir(root)) == ["Personal", "Spaces"]
    assert sorted(os.listdir(root / "Spaces")) == ["Projects"]
    assert sorted(os.listdir(root / "Personal")) == ["read.bin"]
    assert sorted(os.listdir(root / "Spaces/Projects")) == ["read.bin", "write.bin"]
    assert (root / "Personal/read.bin").read_bytes() == expected_p
    assert (root / "Spaces/Projects/read.bin").read_bytes() == expected_s
    assert (root / "Spaces/Projects/write.bin").read_bytes() == (updated if sys.argv[3] == "updated" else original)
    print(json.dumps({"ordinary_reads_exact": True}))
elif mode == "write":
    with open(root / "Spaces/Projects/write.bin", "r+b", buffering=0) as output:
        assert output.read() == original
        output.seek(0)
        assert output.write(updated) == len(updated)
        output.truncate()
        os.fsync(output.fileno())
    assert (root / "Spaces/Projects/write.bin").read_bytes() == updated
    print(json.dumps({"ordinary_write_fsync_close_exact": True}))
elif mode == "hold":
    ready, release = Path(sys.argv[3]), Path(sys.argv[4])
    with open(root / "Personal/read.bin", "rb") as held:
        assert held.read() == expected_p
        ready.write_text(json.dumps({"pid": os.getpid(), "open_file": True}) + "\n")
        deadline = time.monotonic() + 240
        while not release.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("bounded open-file holder expired")
            time.sleep(0.05)
    print(json.dumps({"open_file_released": True}))
else:
    raise RuntimeError("unknown synthetic worker")
'''


class Harness:
    def __init__(self, binaries, output, backend, precreate_private_state=False):
        self.output = output
        self.backend = backend
        self.binaries = ordinary_absolute(binaries)
        for name in ("raiun", "raiun-agent"):
            file = ordinary_absolute(self.binaries / name)
            require(file.is_file() and os.access(file, os.X_OK), "Missing installed production executable")
        self.mount = output / "cloud-root"
        self.mount.mkdir(mode=0o700)
        self.state = output / "state"
        require(not self.state.exists(), "Native state must start absent")
        if precreate_private_state:
            # Explicit compatibility mode for preserved older candidates only.
            self.state.mkdir(mode=0o700)
            require(self.state.stat().st_mode & 0o777 == 0o700, "Fixture state must be mode0700")
        self.config = output / "headless.json"
        write_json(self.config, {"schema_version": 1, "server": backend.origin, "auth": "app_token",
                                "username": USER, "mount_path": str(self.mount), "auto_mount": True,
                                "remember_login": True, "reconnect_interval_seconds": 1, "profile": "default"})
        self.home = output / "home"
        self.home.mkdir(mode=0o700)
        self.environment = dict(os.environ, HOME=str(self.home), DISPLAY="", WAYLAND_DISPLAY="", DBUS_SESSION_BUS_ADDRESS="")
        for name in ("RAIUN_STATE_DIR", "RAIUN_HEADLESS_CONFIG", "RAIUN_HEADLESS_CONTEXT", "XDG_STATE_HOME", "XDG_CONFIG_HOME"):
            self.environment.pop(name, None)
        self.environment.update(RAIUN_STATE_DIR=str(self.state), RAIUN_HEADLESS_CONFIG=str(self.config))
        self.sequence = 0
        self.agent = None
        self.agent_log = None
        self.holder = None
        self.processes = []
        self.transcripts = []
        self.results = {"fixture": "production-linux-fuse-v1", "passed": False,
                        "native_attempted": True, "checks": [], "failures": [], "processes": self.processes,
                        "fixture_state_precreated_mode": "0700" if precreate_private_state else None,
                        "default_state_creation_acceptance": False,
                        "output": str(output), "startup_changed": False, "real_accounts_used": False,
                        "forced_termination": False, "recursive_cleanup": False,
                        "retention": "all binaries, roots, state, credentials, server data and logs retained",
                        "binary_sha256": {name: hashlib.sha256((self.binaries / name).read_bytes()).hexdigest()
                                          for name in ("raiun", "raiun-agent")}}

    def record(self):
        write_json(self.output / "RESULTS.json", self.results)

    def checked(self, name):
        self.results["checks"].append(name)
        self.record()

    def spawn(self, arguments, label, token=False, service=False):
        self.sequence += 1
        info = {"sequence": self.sequence, "label": label}
        prefix = self.output / f"{self.sequence:02d}-{label}"
        info["stdout"] = str(prefix) + ".stdout.log"
        info["stderr"] = str(prefix) + ".stderr.log"
        logs = [open(info[stream], "xb", buffering=0) for stream in ("stdout", "stderr")]
        process = subprocess.Popen(arguments, env=self.environment,
                                   stdin=subprocess.PIPE if token else subprocess.DEVNULL,
                                   stdout=logs[0], stderr=logs[1], start_new_session=service)
        info["pid"] = process.pid
        self.processes.append(info)
        self.record()
        if token:
            try:
                process.stdin.write((TOKEN + "\n").encode())
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        if service:
            return process, logs, info
        try:
            deadline = time.monotonic() + (100 if token else 45)
            while process.poll() is None:
                if any(Path(info[name]).stat().st_size > MAX_LOG for name in ("stdout", "stderr")):
                    info["output_limit"] = True
                    self.record()
                    raise Failure("Task output limit reached; recorded PID retained, no forced termination")
                if time.monotonic() >= deadline:
                    info["timeout"] = True
                    self.record()
                    raise Failure("Task command timed out; recorded PID remains running, no forced termination")
                time.sleep(0.02)
        finally:
            for log in logs:
                log.close()
        info["exit_code"] = process.returncode
        stdout, stderr = (Path(info[name]).read_bytes() for name in ("stdout", "stderr"))
        require(len(stdout) <= MAX_LOG and len(stderr) <= MAX_LOG, "Task output exceeds fixture bound")
        self.transcripts.extend((stdout, stderr))
        self.record()
        require(not any(value in stdout or value in stderr for value in (TOKEN.encode(), BASIC.encode())),
                "Task output exposed a synthetic credential; retain private evidence")
        return process.returncode, stdout, stderr

    def drive(self, *arguments, token=False, success=True):
        label = "cli-" + arguments[0]
        command = [str(self.binaries / "raiun"), "--config", str(self.config), "drive",
                   "--state-dir", str(self.state), "--json", *arguments]
        code, stdout, stderr = self.spawn(command, label, token=token)
        require((code == 0) == success, "Unexpected installed CLI exit status; inspect retained command logs")
        if not success:
            return code, stdout, stderr
        try:
            return json.loads(stdout)
        except ValueError as error:
            raise Failure("Installed CLI returned invalid JSON") from error

    def status(self, connected=True, mounted=True):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status = self.drive("status")
            require(status.get("runtime_mode") == "mount_only", "Agent runtime mode mismatch")
            require(status.get("folder_sync_enabled") is False, "Folder sync unexpectedly enabled")
            if status.get("connected") is connected and status.get("mounted") is mounted and not status.get("restoring") and not status.get("authenticating"):
                require(status.get("credential_storage") == "private_file", "Remembered file credential policy missing")
                return status
            time.sleep(0.1)
        raise Failure("Installed agent did not reach expected connection/mount state")

    def start(self):
        self.agent, self.agent_log, self.agent_info = self.spawn(
            [str(self.binaries / "raiun"), "--config", str(self.config), "drive", "--state-dir", str(self.state), "serve"],
            "agent", service=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(self.agent.poll() is None, "Installed agent exited before IPC readiness")
            if (self.state / "control.sock").is_socket():
                return
            time.sleep(0.05)
        raise Failure("Installed agent socket readiness timed out")

    def stop(self):
        if self.agent is None:
            return
        if self.agent.poll() is None:
            self.drive("stop")
            try:
                self.agent.wait(timeout=30)
            except subprocess.TimeoutExpired as error:
                self.agent_info["timeout"] = True
                self.record()
                raise Failure("Foreground agent did not exit after normal stop; PID retained") from error
        require(self.agent.returncode == 0, "Foreground agent returned failure")
        self.agent_info["exit_code"] = self.agent.returncode
        for log in self.agent_log:
            log.close()
        self.agent_log = None
        self.agent = None
        require(not self.mounted(), "FUSE root remained mounted after normal agent stop")
        self.record()

    def mounted(self):
        expected = str(self.mount).encode().replace(b"\\", b"\\134").replace(b" ", b"\\040")
        # Match the exact kernel mountpoint, not CLI status alone.
        return any(line.split()[4] == expected and b" - fuse" in line
                   for line in Path("/proc/self/mountinfo").read_bytes().splitlines())

    def worker(self, mode, *extra):
        code, stdout, _ = self.spawn([sys.executable, "-c", WORKER, mode, str(self.mount), *extra], "os-" + mode)
        require(code == 0, "Ordinary filesystem operation failed; no fallback/retry was used")
        return json.loads(stdout)

    def busy_unmount(self):
        ready, release = self.output / "holder-ready.json", self.output / "holder-release"
        self.holder, logs, info = self.spawn([sys.executable, "-c", WORKER, "hold", str(self.mount), str(ready), str(release)],
                                           "os-hold", service=True)
        try:
            deadline = time.monotonic() + 15
            while not ready.is_file() and time.monotonic() < deadline:
                require(self.holder.poll() is None, "Open-file holder exited before readiness")
                time.sleep(0.05)
            require(ready.is_file(), "Open-file holder readiness timed out")
            code, _, stderr = self.drive("unmount", success=False)
            require(code != 0 and b"busy" in stderr.lower(), "Open file did not produce explicit busy-unmount refusal")
            self.status(connected=True, mounted=True)
            require(self.mounted(), "Busy unmount detached the actual FUSE mount")
            self.checked("open_file_busy_unmount_refuses_and_keeps_kernel_mount")
        finally:
            release.touch(exist_ok=False)
            try:
                self.holder.wait(timeout=15)
            except subprocess.TimeoutExpired as error:
                info["timeout"] = True
                self.record()
                raise Failure("Open-file holder did not release; PID retained, no forced termination") from error
            finally:
                for log in logs:
                    log.close()
            info["exit_code"] = self.holder.returncode
            require(self.holder.returncode == 0, "Open-file holder failed")
            self.holder = None
        self.drive("unmount")
        self.status(connected=True, mounted=False)
        require(not self.mounted(), "Safe unmount left a kernel FUSE mount")
        self.checked("holder_close_then_normal_cli_unmount")

    def run(self):
        try:
            device = Path("/dev/fuse")
            require(device.exists() and stat.S_ISCHR(device.stat().st_mode), "Hard failure: /dev/fuse character device is missing")
            require(os.access(device, os.R_OK | os.W_OK), "Hard failure: /dev/fuse is inaccessible")
            require(shutil.which("fusermount3") is not None, "Hard failure: fusermount3 is missing")
            self.checked("native_fuse_prerequisites_present")
            self.start()
            require(self.state.stat().st_mode & 0o777 == 0o700, "Agent state directory must be mode0700")
            self.results["default_state_creation_acceptance"] = self.results["fixture_state_precreated_mode"] is None
            self.checked("private_state_directory_admitted")
            self.status(connected=False, mounted=False)
            login = self.drive("login", "--app-token", "--token-stdin", token=True)
            require(login.get("connected") is True and login.get("authentication") == "app_token", "CLI stdin login did not confirm final completion")
            self.status()
            require(self.mounted(), "CLI mounted status has no kernel FUSE mount")
            self.checked("production_cli_stdin_login_and_real_fuse_mount")
            require({space["id"] for space in self.drive("spaces")} == set(ROOTS), "CLI did not list exact Personal/Projects Spaces")
            require(self.worker("read", "original").get("ordinary_reads_exact") is True, "Ordinary initial reads failed")
            self.checked("ordinary_personal_projects_reads_exact")
            require(self.worker("write").get("ordinary_write_fsync_close_exact") is True, "Ordinary conditional write failed")
            snapshot = self.backend.snapshot()
            require(base64.b64decode(snapshot["files"][WRITE_PATH]["body"]) == UPDATED, "Remote fixture bytes differ after ordinary write")
            counts = snapshot["counts"]
            require(counts.get("successful_puts", 0) == 1 and counts.get("put_attempts", 0) == 1 and counts.get("all_mutation_attempts", 0) == 1,
                    "Unexpected or duplicate remote mutation")
            write = snapshot["writes"][0]
            require(write["if_match"] == self.backend.etag(WRITE_PATH, 1) and write["new_etag"] == self.backend.etag(WRITE_PATH, 2), "Conditional write revision binding missing")
            # Independent authenticated readback observes the server's exact new revision.
            status, headers, content = http_request(self.backend.origin, "GET", WRITE_PATH,
                                                     {"If-Match": self.backend.etag(WRITE_PATH, 2)})
            require(status == 200 and headers.get("etag") == self.backend.etag(WRITE_PATH, 2) and content == UPDATED,
                    "Independent exact remote readback failed")
            self.checked("one_if_match_write_and_independent_exact_remote_readback")
            credential = self.state / "sessions/default.json"
            require(credential.is_file() and credential.stat().st_mode & 0o777 == 0o600,
                    "Remembered synthetic credential file missing or permissions too broad")
            require(TOKEN not in self.config.read_text(), "Config contains credential material")
            self.checked("private_remembered_credential_file_without_config_token")
            # Read-only guard RPCs prove ordinary folder-sync mutations remain refused.
            for action in ("sync_now", "pair_add", "set_autostart"):
                code, stdout, _ = self.spawn([str(self.binaries / "raiun-agent"), "request", json.dumps({"action": action})], "guard-" + action)
                require(code == 0 and json.loads(stdout).get("ok") is False, "Mount-only agent admitted a desktop operation")
            self.checked("folder_sync_and_desktop_autostart_rpcs_refused")
            self.busy_unmount()
            self.stop()
            require(credential.is_file(), "Normal stop removed remembered credentials")
            self.checked("normal_first_stop_preserves_saved_credentials")
            self.start()
            self.status()
            require(self.mounted(), "Remembered-session restart did not automount")
            require(self.worker("read", "updated").get("ordinary_reads_exact") is True, "Restart reads did not retain verified write")
            self.checked("remembered_session_restart_automount_without_login_and_updated_reads")
            self.drive("unmount")
            self.status(connected=True, mounted=False)
            require(not self.mounted(), "Second safe unmount left actual FUSE mount")
            self.stop()
            self.checked("second_normal_unmount_and_stop")
            snapshot = self.backend.snapshot()
            counts = snapshot["counts"]
            require(snapshot["server_failures"] == 0 and not any(counts.get(key, 0) for key in (
                "unknown_requests", "unexpected_methods", "authentication_failures", "conditional_read_failures",
                "conditional_write_failures", "root_condition_failures", "unexpected_put_content_or_repeat", "request_log_overflow", "invalid_framing")),
                "Server observed unexpected protocol/authentication/condition failure")
            require(counts.get("all_mutation_attempts") == 1 and counts.get("successful_puts") == 1,
                    "Restart or refused commands issued additional remote mutations")
            for path in FILES:
                require(snapshot["gets"].get(path, 0) > 0, "Expected file had no actual remote content read")
            for path in self.output.glob("*.log"):
                content = path.read_bytes()
                require(TOKEN.encode() not in content and BASIC.encode() not in content,
                        "Credential output redaction failed; private evidence retained")
            self.results["server_snapshot"] = snapshot
            self.checked("redacted_outputs_exact_server_counters_and_no_extra_mutations")
            self.results["passed"] = True
        except Exception as error:
            # Arbitrary OS/remote exception text is not copied into shared receipts.
            self.results["failures"].append(str(error) if isinstance(error, Failure) else "Unexpected harness exception; inspect retained private logs")
        finally:
            if self.holder is not None and self.holder.poll() is None:
                release = self.output / "holder-release"
                if not release.exists():
                    release.touch()
                try:
                    self.holder.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.results["failures"].append("Open-file holder remains active; no forced termination")
            if self.agent is not None and self.agent.poll() is None:
                try:
                    self.drive("unmount")
                    self.stop()
                except Exception:
                    self.results["failures"].append("Graceful cleanup incomplete; inspect recorded agent PID/state, no forced termination")
            if self.agent_log is not None:
                for log in self.agent_log:
                    log.close()
            self.results["server_snapshot"] = self.backend.snapshot()
            if self.results["failures"]:
                self.results["passed"] = False
            self.record()
        require(self.results["passed"], "Native FUSE fixture failed; retain RESULTS.json and all state/logs")


def http_request(origin, method, path, headers=None, body=b"", authorized=True):
    parsed = urlsplit(origin)
    require(parsed.hostname == "127.0.0.1" and parsed.scheme == "http", "Protocol probe is loopback-only")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    merged = {"Content-Length": str(len(body))}
    if authorized:
        merged["Authorization"] = AUTHORIZATION
    merged.update(headers or {})
    try:
        connection.request(method, path, body=body, headers=merged)
        response = connection.getresponse()
        content = response.read(MAX_BODY + 1)
        require(len(content) <= MAX_BODY, "Protocol response exceeds bound")
        return response.status, {name.lower(): value for name, value in response.getheaders()}, content
    finally:
        connection.close()


def protocol_self_test(backend, output):
    passed = False
    try:
        require(http_request(backend.origin, "GET", "/graph/v1.0/me")[0] == 200, "Identity route failed")
        require(http_request(backend.origin, "GET", "/graph/v1.0/me", authorized=False)[0] == 401, "Basic-auth rejection failed")
        status, _, body = http_request(backend.origin, "GET", "/graph/v1.0/me/drives")
        require(status == 200 and {entry["id"] for entry in json.loads(body)["value"]} == set(ROOTS), "Graph discovery failed")
        for root in ROOTS.values():
            for depth in ("0", "1"):
                status, _, body = http_request(backend.origin, "PROPFIND", root, {"Depth": depth})
                xml = ET.fromstring(body)
                expected = 1 if depth == "0" else 1 + sum(name.startswith(root) for name in FILES)
                require(status == 207 and len(xml.findall("{DAV:}response")) == expected, "DAV depth response failed")
        etag = backend.etag(WRITE_PATH, 1)
        status, headers, body = http_request(backend.origin, "GET", WRITE_PATH, {"If-Match": etag, "Range": "bytes=2-5"})
        require(status == 206 and body == ORIGINAL[2:6] and headers["content-range"] == f"bytes 2-5/{len(ORIGINAL)}", "Conditional range failed")
        require(http_request(backend.origin, "GET", WRITE_PATH, {"If-Match": '"wrong"'})[0] == 412, "Read ETag refusal failed")
        require(http_request(backend.origin, "PUT", WRITE_PATH, {"If-Match": '"wrong"'}, UPDATED)[0] == 412, "Write ETag refusal failed")
        require(http_request(backend.origin, "PUT", WRITE_PATH, {"If-Match": etag}, UPDATED)[0] == 204, "Conditional update failed")
        new_etag = backend.etag(WRITE_PATH, 2)
        status, headers, body = http_request(backend.origin, "GET", WRITE_PATH, {"If-Match": new_etag})
        require(status == 200 and headers["etag"] == new_etag and body == UPDATED, "Updated remote exact readback failed")
        require(http_request(backend.origin, "DELETE", WRITE_PATH)[0] == 405, "Unknown mutation method not rejected")
        require(http_request(backend.origin, "PUT", ROOTS["project"] + "unknown.bin", body=b"unknown")[0] == 404, "Unknown mutation route not rejected")
        snapshot = backend.snapshot()
        require(snapshot["counts"]["all_mutation_attempts"] == 4 and snapshot["counts"]["successful_puts"] == 1,
                "Global mutation accounting omitted a rejected route")
        require(snapshot["server_failures"] == 0, "Synthetic server failed internally")
        passed = True
    finally:
        write_json(output / "RESULTS.json", {"fixture": "linux-fuse-backend-protocol-v1", "passed": passed,
                   "native_fuse_executed": False, "production_agent_executed": False, "server_snapshot": backend.snapshot()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-native", action="store_true", help="Actually sign in to the synthetic account and mount FUSE on the authorized VM")
    mode.add_argument("--serve-only", action="store_true", help="Run only a persistent synthetic loopback backend; no Raiun/startup/mount")
    mode.add_argument("--protocol-self-test", action="store_true", help="Check only synthetic HTTP protocol; no agent/FUSE")
    parser.add_argument("--binaries", type=Path, help="Absolute installed production binary directory")
    parser.add_argument("--output", type=Path, help="Absolute NEW retained evidence directory")
    parser.add_argument("--port", type=int, default=0, help="Loopback port; serve-only requires an explicit fixed nonzero port")
    parser.add_argument("--server-state", type=Path, help="Absolute synthetic server JSON state; serve-only may reopen its own retained state")
    parser.add_argument("--precreate-private-state", action="store_true", help="Compatibility only: precreate0700 state; does not accept application state creation")
    args = parser.parse_args()
    require(0 <= args.port <= 65535, "Invalid loopback port")
    if args.serve_only:
        require(args.port > 0 and args.server_state is not None, "Serve-only needs --port FIXED and --server-state ABS")
        state = ordinary_absolute(args.server_state)
        backend = Backend(state)
    else:
        require(args.output is not None, "Native/protocol mode requires --output NEWPATH")
        if args.run_native:
            require(args.binaries is not None, "Native mode requires --binaries PATH")
        output = ordinary_absolute(args.output)
        require(not output.exists(), "Evidence output already exists; preserve it and choose a fresh path")
        output.mkdir(mode=0o700)
        state = ordinary_absolute(args.server_state) if args.server_state else output / "server-state.json"
        require(not state.exists(), "Native/protocol acceptance requires fresh server state")
        backend = Backend(state)
    server = Server(backend, args.port)
    thread = threading.Thread(target=server.serve_forever, name="synthetic-loopback-server", daemon=True)
    thread.start()
    try:
        if args.serve_only:
            ready = {"fixture": STATE_FORMAT, "origin": backend.origin, "pid": os.getpid(), "loopback_only": True,
                     "server_state": str(state), "startup_changed": False, "native_fuse_executed": False}
            write_json(state.with_name(state.name + ".ready.json"), ready)
            print(json.dumps(ready), flush=True)
            stopping = threading.Event()
            for signum in (signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, lambda *_: stopping.set())
            while not stopping.wait(1):
                pass
        elif args.protocol_self_test:
            protocol_self_test(backend, output)
            print(json.dumps({"protocol_checks": "passed", "native_fuse_executed": False, "output": str(output)}))
        else:
            Harness(args.binaries, output, backend, args.precreate_private_state).run()
            print(json.dumps({"native_fuse_fixture": "passed", "output": str(output), "all_files_retained": True}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        backend.close()


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        print("error: " + str(error), file=sys.stderr)
        raise SystemExit(1)
