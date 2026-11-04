# Opt-in Linux FUSE acceptance

Run this synthetic fixture only on an authorized disposable Linux environment
with `/dev/fuse`, FUSE 3 and Python 3 available. It launches the production CLI
and agent, signs into a fixed synthetic loopback account and actually mounts a
task-owned FUSE root. It does not use a real account, enable folder sync, change
startup or modify a regular installation.

```sh
python3 /ABS/test-headless-fuse-linux.py --run-native \
  --binaries /ABS/installed-headless-binaries \
  --output /ABS/new-retained-evidence-directory
```

The output directory must not already exist. The default test leaves state
creation to the agent and checks mode `0700`, including when the invoking user's
umask permits group writes. Existing writable state is still refused. The
explicit `--precreate-private-state` compatibility option is for investigating
older candidates; its receipt does not count as state-creation acceptance.

The test requires ordinary Personal and Projects reads, one conditional ordinary
write, exact remote ETag-bound readback, a private remembered credential file,
folder-sync refusal, actual busy-unmount refusal while an ordinary handle is
open, normal unmount after closing that handle, and saved-session restart with
automount and the updated file bytes. Status alone is insufficient: actual
kernel mount state is checked.

Commands and I/O workers have bounded waits and retain PIDs on timeout. The
fixture attempts normal unmount/stop; it never force-kills a provider, lazily
detaches a mount or recursively deletes evidence. All root/state/configuration,
synthetic credentials, server data, output and process receipts remain retained.
Inspect `RESULTS.json` and recorded PIDs if graceful shutdown is incomplete.

`--protocol-self-test --output /ABS/new-directory` checks only the synthetic
HTTP protocol. It does not execute Raiun or prove FUSE acceptance. The separate
`--serve-only --port FIXED --server-state /ABS/state.json` mode supplies a
persistent loopback-only synthetic backend for explicitly prepared VM startup
tests; it does not register a service itself.

Ordinary fixture restart does not establish system boot. Before-login service
acceptance needs a separately controlled reboot and observations before the
test user's first login, with a backend available across reboot. See
[HEADLESS-STARTUP.md](HEADLESS-STARTUP.md) and
[HEADLESS-ACCEPTANCE.md](HEADLESS-ACCEPTANCE.md).
