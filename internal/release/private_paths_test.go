package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the release gate against Git's real index: quoted Unicode paths
// must not hide a private capability matrix from the publication check.
func TestReleaseGateRejectsTrackedPrivatePaths(t *testing.T) {
	for _, command := range []string{"bash", "git", "python"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is required for the shell release gate", command)
		}
	}
	gate, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-p5.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		path        string
		wantFailure bool
	}{
		{"public example", ".env.example", false},
		{"environment", ".env", true},
		{"nested upstreams", "scripts/upstreams.tsv", true},
		{"Unicode matrix", "docs/02-上游能力矩阵.md", true},
		{"custom DB backup secrets", "custom-runtime/backups/rotation/secrets.json", true},
		{"custom DB backup database", "custom-runtime/backups/rotation/database.sqlite", true},
		{"restore staging secrets", "custom-runtime/.secrets-restore-123/keyring.json", true},
		{"isolated old secrets", "custom-runtime/isolated-20261018/secrets/keyring.json", true},
		{"live keyring outside data", "custom-runtime/secrets/keyring.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, body string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("scripts/check-p5.sh", string(gate), 0700)
			write("docs/RELEASE-NOTES-v1.0.0.md", "真实公网证书仍未验证\n", 0600)
			write("docs/09-P5-发布验证.md", "Offline gate fixture\n", 0600)
			write(tc.path, "public test fixture, no credentials\n", 0600)
			// The package tests run separately. This fixture isolates the shell
			// gate's publication decision without building Go recursively.
			write("bin/go", "#!/bin/sh\nexit 0\n", 0700)
			for _, args := range [][]string{
				{"init", "-q"},
				{"config", "core.quotePath", "true"},
				{"add", "--", tc.path},
			} {
				cmd := exec.Command("git", args...)
				cmd.Dir = root
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			cmd := exec.Command("bash", "scripts/check-p5.sh")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"), "PYTHONUTF8=1")
			out, err := cmd.CombinedOutput()
			if tc.wantFailure {
				if err == nil || !strings.Contains(string(out), "tracked forbidden path:") {
					t.Fatalf("private path %q must be rejected: err=%v\n%s", tc.path, err, out)
				}
			} else if err != nil {
				t.Fatalf("public example must be allowed: %v\n%s", err, out)
			}
		})
	}
}
