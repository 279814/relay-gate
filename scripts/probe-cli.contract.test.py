#!/usr/bin/env python3
"""Run the actual thin wrappers with a disposable binary and synthetic stdin."""
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


@unittest.skipUnless(BASH, "Bash unavailable")
class ProbeWrapperContract(unittest.TestCase):
    def invoke(self, wrapper, args, body=""):
        with tempfile.TemporaryDirectory(prefix="relay-cli-wrapper-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "tmp").mkdir()
            shutil.copyfile(ROOT / wrapper, root / wrapper)
            helper = ROOT / "scripts/probe-cli-wrapper.sh"
            if helper.exists():
                shutil.copyfile(helper, root / "scripts/probe-cli-wrapper.sh")
            binary = root / "fixture-binary"
            binary.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$CLI_WRAPPER_ARGS\"\ncat > \"$CLI_WRAPPER_STDIN\"\nexit 42\n", encoding="utf-8")
            binary.chmod(0o700)
            args_path, stdin_path = root / "argv.txt", root / "stdin.txt"
            env = dict(os.environ, TMPDIR=bash_path(root / "tmp"), RELAY_GATE_BIN=bash_path(binary), CLI_WRAPPER_ARGS=bash_path(args_path), CLI_WRAPPER_STDIN=bash_path(stdin_path))
            result = subprocess.run([BASH, bash_path(root / wrapper), *args], input=body, text=True, encoding="utf-8", errors="replace", capture_output=True, env=env, cwd=root, timeout=20)
            return result, args_path.read_text() if args_path.exists() else "", stdin_path.read_text() if stdin_path.exists() else ""

    def test_wrappers_forward_only_explicit_authorization_and_key_free_arguments(self):
        credential = "synthetic-wrapper-stdin-only-credential"
        data = f"fixture\thttps://fixture.invalid\t{credential}\tmodel\t-\n"
        for script, command in (("scripts/probe-all.sh", "probe-matrix"), ("scripts/probe-upstream.sh", "probe-one")):
            with self.subTest(script=script):
                result, args, stdin = self.invoke(script, ["--online", "--accept-probe-cost", "--input", "-", "--name", "fixture"], data)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(args.splitlines()[0], command)
                self.assertNotIn(credential, args + result.stdout + result.stderr)
                self.assertEqual(stdin, data)

    def test_legacy_key_argv_missing_authorization_and_unknown_flags_never_exec(self):
        cases = [
            ["https://fixture.invalid", "synthetic-legacy-key", "model", "-", "fixture"],
            ["--input", "-", "--name", "fixture"],
            ["--online", "--input", "-", "--name", "fixture"],
            ["--online", "--accept-probe-cost", "--control-manifest", "manifest.json", "--input", "-", "--name", "fixture"],
            ["--online", "--accept-probe-cost", "--accept-unknown", "--input", "-"],
        ]
        for script in ("scripts/probe-all.sh", "scripts/probe-upstream.sh"):
            for case in cases:
                with self.subTest(script=script, case=case):
                    result, args, stdin = self.invoke(script, case)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(args, "", result.stderr)
                    self.assertEqual(stdin, "")
                    self.assertNotIn("synthetic-legacy-key", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
