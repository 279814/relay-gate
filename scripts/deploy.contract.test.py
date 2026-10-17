#!/usr/bin/env python3
"""Run the real installers offline; Docker, HTTP and waits stay inside a temp dir."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash")
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


def bash_path(path):
    value = str(path).replace("\\", "/")
    return "/" + value[0].lower() + value[2:] if os.name == "nt" else value


DOCKER = r'''#!/usr/bin/env bash
printf '%s\n' "docker $*" >> "$DEPLOY_TEST_CALLS"
case "$1 $2" in
  'compose up') exit "$DEPLOY_TEST_UP_EXIT" ;;
  'compose port')
    printf '%s' "$DEPLOY_TEST_BINDINGS"
    exit "$DEPLOY_TEST_PORT_EXIT" ;;
  'compose logs')
    if [[ " $* " == *' --no-log-prefix '* ]]; then
      printf 'ADMIN_PASSWORD=fixture-admin\nRELAY_KEYS=fixture-relay\nENCRYPTION_KEY=fixture-master\n'
    else
      printf 'relay-gate | %s\n' 'ADMIN_PASSWORD=fixture-admin' 'RELAY_KEYS=fixture-relay' 'ENCRYPTION_KEY=fixture-master'
    fi ;;
  *) echo "unexpected Docker call: $*" >&2; exit 99 ;;
esac
'''

CURL = r'''#!/usr/bin/env bash
printf '%s\n' "curl $*" >> "$DEPLOY_TEST_CALLS"
[[ " ${*: -1} " == " http://127.0.0.1:$DEPLOY_TEST_EXPECTED_PORT/healthz " ]]
'''

PS_LAUNCHER = r'''
$ErrorActionPreference = 'Stop'
function docker {
    [IO.File]::AppendAllText($env:DEPLOY_TEST_CALLS, "docker $($args -join ' ')`n")
    $global:LASTEXITCODE = 0
    switch ($args[0..1] -join ' ') {
        'info' { return }
        'compose up' { $global:LASTEXITCODE = [int]$env:DEPLOY_TEST_UP_EXIT; return }
        'compose port' {
            $global:LASTEXITCODE = [int]$env:DEPLOY_TEST_PORT_EXIT
            if ($env:DEPLOY_TEST_BINDINGS) { $env:DEPLOY_TEST_BINDINGS -split "`n" }
            return
        }
        'compose logs' {
            if ('--no-log-prefix' -in $args) {
                'ADMIN_PASSWORD=fixture-admin'
                'RELAY_KEYS=fixture-relay'
                'ENCRYPTION_KEY=fixture-master'
            } else {
                'relay-gate | ADMIN_PASSWORD=fixture-admin'
                'relay-gate | RELAY_KEYS=fixture-relay'
                'relay-gate | ENCRYPTION_KEY=fixture-master'
            }
            return
        }
        default {
            # docker info has no second argument.
            if ($args[0] -eq 'info') { return }
            throw "unexpected Docker call: $args"
        }
    }
}
function Invoke-WebRequest {
    param([string]$Uri, [switch]$UseBasicParsing, [int]$TimeoutSec)
    [IO.File]::AppendAllText($env:DEPLOY_TEST_CALLS, "health $Uri`n")
    if ($Uri -ne "http://127.0.0.1:$($env:DEPLOY_TEST_EXPECTED_PORT)/healthz") {
        throw 'wrong health port'
    }
    [pscustomobject]@{ StatusCode = 200 }
}
function Start-Sleep { param([int]$Seconds) }
if ($env:DEPLOY_TEST_LOG_COMMAND) {
    Invoke-Expression $env:DEPLOY_TEST_LOG_COMMAND
} else {
    & $env:DEPLOY_TEST_SCRIPT
    exit $LASTEXITCODE
}
'''


class DeployContract(unittest.TestCase):
    def run_installer(self, shell, *, bindings="0.0.0.0:18787\n", expected=18787,
                      dotenv=None, env_port=None, up_exit=0, port_exit=0, verify_logs=False):
        # Only installer copies run: their data/ and optional .env never touch user data.
        with tempfile.TemporaryDirectory(prefix="relay-deploy-contract-") as directory:
            root = Path(directory)
            script = root / ("deploy.sh" if shell == "bash" else "deploy.ps1")
            shutil.copyfile(ROOT / script.name, script)
            if dotenv is not None:
                (root / ".env").write_text(f"RELAY_PORT={dotenv}\n", encoding="utf-8")
            calls = root / "calls.log"
            env = dict(os.environ)
            env.pop("RELAY_PORT", None)
            env.pop("DEPLOY_TEST_LOG_COMMAND", None)
            if env_port is not None:
                env["RELAY_PORT"] = str(env_port)
            env.update(DEPLOY_TEST_BINDINGS=bindings, DEPLOY_TEST_EXPECTED_PORT=str(expected),
                       DEPLOY_TEST_UP_EXIT=str(up_exit), DEPLOY_TEST_PORT_EXIT=str(port_exit),
                       DEPLOY_TEST_CALLS=str(calls), DEPLOY_TEST_SCRIPT=str(script))
            if shell == "bash":
                if not BASH:
                    self.skipTest("Bash required for shell installer contracts")
                tools = root / "bin"
                tools.mkdir()
                for name, source in (("docker", DOCKER), ("curl", CURL),
                                     ("sleep", "#!/bin/sh\nexit 0\n")):
                    path = tools / name
                    path.write_text(source, encoding="utf-8", newline="\n")
                    path.chmod(0o755)
                env["DEPLOY_TEST_BIN"] = bash_path(tools)
                env["DEPLOY_TEST_SCRIPT"] = bash_path(script)
                env["DEPLOY_TEST_CALLS"] = bash_path(calls)
                command = [BASH, "-c", 'export PATH="$DEPLOY_TEST_BIN:$PATH"; exec bash "$DEPLOY_TEST_SCRIPT"']
            else:
                if not POWERSHELL:
                    self.skipTest("PowerShell required for PowerShell installer contracts")
                launcher = root / "launch.ps1"
                launcher.write_text(PS_LAUNCHER, encoding="utf-8-sig")
                command = [POWERSHELL, "-NoProfile", "-File", str(launcher)]
            result = subprocess.run(command, env=env, cwd=root, text=True, encoding="utf-8", errors="replace",
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
            if verify_logs:
                self.assertEqual(result.returncode, 0, result.stdout)
                log_command = next(line.strip() for line in result.stdout.splitlines()
                                   if line.strip().startswith("docker compose logs "))
                if shell == "bash":
                    command = [BASH, "-c", 'export PATH="$DEPLOY_TEST_BIN:$PATH"; ' + log_command]
                else:
                    env["DEPLOY_TEST_LOG_COMMAND"] = log_command
                result = subprocess.run(command, env=env, cwd=root, text=True, encoding="utf-8", errors="replace",
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
            return result, calls.read_text(encoding="utf-8") if calls.exists() else ""

    def test_published_port_drives_health_and_access_url(self):
        cases = [
            ("default", {}, 18787),
            ("dotenv", dict(bindings="0.0.0.0:19991\n", dotenv=19991), 19991),
            ("environment wins", dict(bindings="0.0.0.0:20002\n", dotenv=19991,
                                      env_port=20002), 20002),
            ("IPv6 first", dict(bindings="[::]:20003\n0.0.0.0:20003\n"), 20003),
        ]
        for shell in ("bash", "powershell"):
            for name, options, expected in cases:
                with self.subTest(shell=shell, case=name):
                    result, calls = self.run_installer(shell, expected=expected, **options)
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertIn(f"http://127.0.0.1:{expected}/healthz", calls)
                    self.assertIn(f"http://<this-host-IP>:{expected}/admin/", result.stdout)
                    self.assertIn("docker compose port relay-gate 18787", calls)
                    if shell == "bash":
                        self.assertIn("--connect-timeout", calls)
                        self.assertIn("--max-time", calls)

    def test_compose_errors_or_invalid_bindings_stop_before_health(self):
        cases = [
            ("compose up fails", dict(up_exit=19)),
            ("port query fails", dict(port_exit=20)),
            ("no published port", dict(bindings="")),
            ("malformed binding", dict(bindings="not-a-binding\n")),
            ("missing host", dict(bindings=":18787\n")),
            ("port zero", dict(bindings="0.0.0.0:0\n")),
            ("port outside range", dict(bindings="0.0.0.0:65536\n")),
        ]
        for shell in ("bash", "powershell"):
            for name, options in cases:
                with self.subTest(shell=shell, case=name):
                    result, calls = self.run_installer(shell, **options)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertNotIn("/healthz", calls, result.stdout)
                    if not options.get("up_exit"):
                        self.assertRegex(result.stdout, r"(?i)published port|between 1 and 65535")

    def test_printed_log_command_extracts_all_three_secrets(self):
        for shell in ("bash", "powershell"):
            with self.subTest(shell=shell):
                result, _ = self.run_installer(shell, verify_logs=True)
                self.assertEqual(result.returncode, 0, result.stdout)
                for value in ("fixture-admin", "fixture-relay", "fixture-master"):
                    self.assertIn(value, result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
