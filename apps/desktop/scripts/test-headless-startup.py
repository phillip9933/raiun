#!/usr/bin/env python3
"""Synthetic startup dry-run checks; never enables startup or contacts COM."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True, type=Path)
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    app = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='raiun-startup-render-') as temporary:
        root = Path(temporary)
        state = root / 'state with $literal%'
        state.mkdir()
        config = root / "owner's config.json"
        config.write_text(json.dumps({
            'schema_version': 1, 'server': 'https://synthetic.example.test',
            'auth': 'app_token', 'username': 'synthetic-user',
            'mount_path': str(root / 'mount'), 'auto_mount': True,
            'remember_login': True, 'reconnect_interval_seconds': 30,
            'profile': 'default',
        }))
        home = root / 'home'
        home.mkdir()
        binaries = root / 'fake-bin'
        binaries.mkdir()
        calls = root / 'unexpected-service-call'
        for name in ['systemctl', 'loginctl']:
            program = binaries / name
            program.write_text('#!/bin/sh\nprintf called > "$RAIUN_STARTUP_CALL_RECEIPT"\nexit 91\n')
            program.chmod(0o755)
        environment = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                           RAIUN_STARTUP_CALL_RECEIPT=str(calls))
        environment['PATH'] = str(binaries) + os.pathsep + environment.get('PATH', '')
        base = [str(cli), '--config', str(config), 'drive', '--state-dir', str(state), 'startup']
        before = {str(path.relative_to(root)) for path in root.rglob('*')}
        unit = None
        windows = sys.platform == 'win32'
        for action in ['enable', 'disable', 'status']:
            result = subprocess.run(base + [action, '--dry-run'], env=environment,
                                    text=True, capture_output=True, check=True, timeout=15)
            if windows:
                plan = json.loads(result.stdout)
                assert plan['backend'] == 'native_task_scheduler'
                assert plan['dry_run'] is True and plan['account_resolved'] is False
                assert plan['action'] == action and plan['mode'] == 'boot'
                assert plan['argument_vector'] == ['--config', str(config), 'drive', '--state-dir', str(state), 'serve']
                assert plan['normal_stop_argument_vector'] == ['--config', str(config), 'drive', '--state-dir', str(state), 'stop']
                assert plan['script_host_required'] is False and plan['password_in_arguments_or_files'] is False
                assert plan['forced_termination'] is False and plan['inactive_wait_seconds'] == 330
                assert plan['new_task_password_input'] == ('hidden_console' if action == 'enable' else 'none')
            else:
                assert 'ExecStart=' in result.stdout and ' serve\n' in result.stdout
                assert 'ExecStop=' not in result.stdout
                assert 'KillSignal=SIGTERM\n' in result.stdout
                assert 'TimeoutStopSec=330s\n' in result.stdout
                assert 'SendSIGKILL=no' in result.stdout
                if action == 'enable':
                    assert 'loginctl enable-linger' in result.stdout
                    unit = result.stdout[result.stdout.index('# Raiun headless CLI startup v1'):].split('Action:', 1)[0].rstrip() + '\n'
            assert not calls.exists(), 'Dry-run attempted to contact a service manager'
        result = subprocess.run(base + ['enable', '--mode', 'logon', '--dry-run'],
                                env=environment, text=True, capture_output=True, check=True, timeout=15)
        if windows:
            plan = json.loads(result.stdout)
            assert plan['mode'] == 'logon' and plan['logon_type'] == 'interactive_token'
            assert plan['new_task_password_input'] == 'none' and plan['same_account_elevation_required'] is False
        else:
            assert 'Action: loginctl enable-linger' not in result.stdout
        assert before == {str(path.relative_to(root)) for path in root.rglob('*')}, 'Dry-run wrote files'
        assert not calls.exists()
        analyze = shutil.which('systemd-analyze') if not windows else None
        if analyze:
            rendered = root / 'raiun-headless-test.service'
            rendered.write_text(unit)
            subprocess.run([analyze, 'verify', '--user', '--man=no', str(rendered)],
                           env=environment, text=True, check=True, timeout=15)
        # The native boundary owns XML/COM binding tests. CLI runtime must not
        # regress to a script-host process or an embedded startup helper.
        source = (app / 'crates/raiun-cli/src/startup.rs').read_text()
        production = source[:source.index('#[cfg(test)]\nmod tests')]
        assert 'powershell.exe' not in production and 'windows_script' not in production
        assert 'include_str!' not in production and 'Get-Credential' not in production
        native_run = production[production.index('fn windows_run('):]
        assert native_run.index('if args.dry_run') < native_run.index('TaskScheduler::connect')
        assert 'Zeroizing::new' in native_run and 'rpassword::prompt_password' in native_run
        assert 'normal_windows_cli_stop(config, state, executable)' in native_run
        assert 'wait_observed(&spec, std::time::Duration::from_secs(330))' in native_run
        print(json.dumps({'dry_run_actions': 4, 'service_manager_calls': 0,
                          'writes_during_dry_run': 0, 'systemd_static_verify': bool(analyze),
                          'native_windows_json_plans': 4 if windows else 0, 'native_runtime_source_guards': True,
                          'startup_enabled': False, 'native_windows_boot_acceptance': 'pending'}))


if __name__ == '__main__':
    main()
