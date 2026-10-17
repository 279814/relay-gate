#!/usr/bin/env python3
"""Execute the real public installer with offline Docker/HTTP process doubles."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash")


def bash_path(path):
    value = str(path).replace("\\", "/")
    return "/" + value[0].lower() + value[2:] if os.name == "nt" else value


DOCKER = r'''#!/usr/bin/env bash
printf '%s\n' "docker $*" >> "$PUBLIC_TEST_CALLS"
case " $* " in
  *' version '*) exit 0 ;;
  *' --check-ip '*)
    [[ "$PUBLIC_TEST_IP_VALID" == 1 ]] || exit 4
    printf '%s\n' "$PUBLIC_TEST_CANONICAL_IP" ;;
  *' --status '*)
    printf '{"format_version":1,"phase":"%s","business_allowed":%s}\n' "$PUBLIC_TEST_PHASE" "$PUBLIC_TEST_ALLOWED" ;;
  *' ps -q relay-gate '*) [[ "$PUBLIC_TEST_EXISTING_HTTP" == 1 ]] && echo fixture-http; exit 0 ;;
  *' build public-edge '*|*' up -d --build '*|*' down --timeout 35 '*|*' kill --signal SIGUSR1 public-edge '*) exit "$PUBLIC_TEST_UP_EXIT" ;;
  *) echo "unexpected Docker operation: $*" >&2; exit 97 ;;
esac
'''


class PublicDeployContract(unittest.TestCase):
    def run_install(self, args, *, phase="live_https", valid=True, allowed=True,
                    existing_http=False, up_exit=0, canonical="8.8.8.8"):
        if not BASH:
            self.skipTest("Bash required")
        with tempfile.TemporaryDirectory(prefix="relay-public-installer-") as directory:
            root = Path(directory)
            for name in ("deploy.sh", "deploy-public.sh"):
                if (ROOT / name).exists():
                    shutil.copyfile(ROOT / name, root / name)
            (root / "deploy").mkdir()
            shutil.copyfile(ROOT / "deploy/compose.public.yaml", root / "deploy/compose.public.yaml")
            (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            tools = root / "bin"
            tools.mkdir()
            for name, body in (("docker", DOCKER), ("uname", "#!/bin/sh\necho Linux\n"),
                               ("curl", "#!/bin/sh\necho 8.8.8.8\n"), ("sleep", "#!/bin/sh\nexit 0\n")):
                file = tools / name
                file.write_text(body, encoding="utf-8", newline="\n")
                file.chmod(0o755)
            calls = root / "calls.log"
            env = dict(os.environ)
            env.update(PUBLIC_TEST_BIN=bash_path(tools), PUBLIC_TEST_SCRIPT=bash_path(root / "deploy.sh"),
                       PUBLIC_TEST_CALLS=bash_path(calls), PUBLIC_TEST_PHASE=phase,
                       PUBLIC_TEST_IP_VALID=str(int(valid)), PUBLIC_TEST_ALLOWED=str(allowed).lower(),
                       PUBLIC_TEST_CANONICAL_IP=canonical, PUBLIC_TEST_UP_EXIT=str(up_exit),
                       PUBLIC_TEST_EXISTING_HTTP=str(int(existing_http)))
            result = subprocess.run([BASH, "-c", 'export PATH="$PUBLIC_TEST_BIN:$PATH"; exec bash "$PUBLIC_TEST_SCRIPT" "$@"', "fixture", *args],
                                    env=env, cwd=root, text=True, encoding="utf-8", errors="replace",
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
            return result, calls.read_text(encoding="utf-8") if calls.exists() else "", (root / "data-public/public.env").read_text() if (root / "data-public/public.env").exists() else ""

    def test_confirmation_is_required_before_docker_or_data_mutations(self):
        for args in (("--public", "--ip", "8.8.8.8"), ("--public", "--ip", "8.8.8.8", "--confirm-ip", "9.9.9.9")):
            result, calls, saved = self.run_install(args)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(calls, "", result.stdout)
            self.assertEqual(saved, "")

    def test_confirmed_target_uses_only_public_compose(self):
        result, calls, saved = self.run_install(["--public", "--ip", "8.8.8.8", "--confirm-ip", "8.8.8.8"])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("compose.public.yaml", calls)
        self.assertIn("--check-ip", calls)
        self.assertIn("RELAY_PUBLIC_IP=8.8.8.8", saved)
        self.assertIn("RELAY_PUBLIC_ORIGIN=https://8.8.8.8", saved)
        self.assertNotIn("compose up -d --build", calls)
        self.assertNotIn("18787/healthz", calls)

    def test_private_target_and_compose_errors_fail_closed(self):
        for options in (dict(valid=False), dict(up_exit=8), dict(phase="failed", allowed=False), dict(phase="expired", allowed=False)):
            result, calls, _ = self.run_install(["--public", "--ip", "8.8.8.8", "--confirm-ip", "8.8.8.8"], **options)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("compose up -d --build", calls)
            self.assertNotIn("http://<this-host-IP>", result.stdout)

    def test_existing_http_listener_is_removed_before_public_up(self):
        result, calls, _ = self.run_install(["--public", "--ip", "8.8.8.8", "--confirm-ip", "8.8.8.8"], existing_http=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("down --timeout 35", calls)
        self.assertLess(calls.index("down --timeout 35"), calls.index("up -d --build"))

    def test_ipv6_origin_has_brackets(self):
        ip = "2001:4860::8888"
        result, _, saved = self.run_install(["--public", "--ip", ip, "--confirm-ip", ip], canonical=ip)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"RELAY_PUBLIC_ORIGIN=https://[{ip}]", saved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
