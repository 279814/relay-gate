package config

import (
	"path/filepath"
	"testing"
)

func edgeConfigEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("RELAY_DB", filepath.Join(t.TempDir(), "relay.db"))
	t.Setenv("ENCRYPTION_KEY", "fixture-edge-config-master")
	t.Setenv("RELAY_KEYS", "fixture-edge-config-relay")
	t.Setenv("ADMIN_PASSWORD", "fixture-edge-config-admin")
	t.Setenv("RELAY_TRUSTED_PROXY_IPS", "")
	t.Setenv("RELAY_PUBLIC_ORIGIN", "")
	t.Setenv("RELAY_PUBLIC_HTTPS_STATUS_FILE", "")
}

func TestLoadRejectsIncompleteOrBroadTrustedEdgeConfiguration(t *testing.T) {
	for _, values := range []struct{ peers, origin string }{
		{"0.0.0.0/0", "https://203.0.113.50"},
		{"172.30.187.2", ""},
		{"", "https://203.0.113.50"},
		{"172.30.187.2", "http://203.0.113.50"},
	} {
		t.Run(values.peers+values.origin, func(t *testing.T) {
			edgeConfigEnvironment(t)
			t.Setenv("RELAY_TRUSTED_PROXY_IPS", values.peers)
			t.Setenv("RELAY_PUBLIC_ORIGIN", values.origin)
			if _, err := Load(); err == nil {
				t.Fatal("invalid trusted-edge configuration was ignored at startup")
			}
		})
	}
}

func TestLoadKeepsDefaultHTTPAndLoadsExplicitPublicEdge(t *testing.T) {
	edgeConfigEnvironment(t)
	plain, err := Load()
	if err != nil || plain.TrustedEdge != nil || plain.PublicHTTPSStatusFile != "" {
		t.Fatalf("default HTTP behavior changed: %v", err)
	}
	t.Setenv("RELAY_TRUSTED_PROXY_IPS", "172.30.187.2")
	t.Setenv("RELAY_PUBLIC_ORIGIN", "https://203.0.113.50")
	statusPath := filepath.Join(t.TempDir(), "state.json")
	t.Setenv("RELAY_PUBLIC_HTTPS_STATUS_FILE", statusPath)
	public, err := Load()
	if err != nil || public.TrustedEdge == nil || public.PublicHTTPSStatusFile != statusPath {
		t.Fatalf("public edge configuration was not loaded: %v", err)
	}
}
