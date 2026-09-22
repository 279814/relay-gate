package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/credential"
	"github.com/279814/relay-gate/internal/store"
)

func TestAuth_Argon2HashLoginAndBearer(t *testing.T) {
	dir := t.TempDir()
	pw := "argon2-admin-password"
	hash, err := credential.HashAdminPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.WritePersisted(dir, credential.Persisted{
		FormatVersion: 1, AdminPasswordHash: hash, RelayKey: "rk-x", MasterKeyID: "kid",
	}); err != nil {
		t.Fatal(err)
	}

	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithAdminHash(hash, dir)
	// No env plaintext — hash only.
	h := s.Routes("")

	login := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/api/login",
		strings.NewReader(`{"password":"`+pw+`"}`))
	h.ServeHTTP(login, req)
	if login.Code != http.StatusOK {
		t.Fatalf("hash login: %d %s", login.Code, login.Body.String())
	}

	bearer := httptest.NewRecorder()
	breq := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	breq.Header.Set("Authorization", "Bearer "+pw)
	h.ServeHTTP(bearer, breq)
	if bearer.Code != http.StatusOK {
		t.Fatalf("hash bearer: %d %s", bearer.Code, bearer.Body.String())
	}

	bad := httptest.NewRecorder()
	breq2 := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
	breq2.Header.Set("Authorization", "Bearer wrong-password!!")
	h.ServeHTTP(bad, breq2)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong hash bearer want 401 got %d", bad.Code)
	}
}

func TestAuth_EnvPlaintextStillWorksAlongsideHash(t *testing.T) {
	dir := t.TempDir()
	envPW := "env-admin-password"
	hashPW := "hash-admin-password"
	hash, err := credential.HashAdminPassword(hashPW)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithAdminHash(hash, dir)
	h := s.Routes(envPW)

	for _, pw := range []string{envPW, hashPW} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin/api/upstreams", nil)
		req.Header.Set("Authorization", "Bearer "+pw)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pw %q: %d %s", pw, rec.Code, rec.Body.String())
		}
	}
}

func TestResetAdminPersistsHash(t *testing.T) {
	dir := t.TempDir()
	old := "old-admin-password"
	hash, err := credential.HashAdminPassword(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.WritePersisted(dir, credential.Persisted{
		FormatVersion: 1, AdminPasswordHash: hash, RelayKey: "rk-x", MasterKeyID: "kid",
	}); err != nil {
		t.Fatal(err)
	}
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	s := New(st, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithAdminHash(hash, dir)
	h := s.Routes(old)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/api/credentials/reset-admin",
		strings.NewReader(`{"password":"`+old+`"}`))
	req.Header.Set("Authorization", "Bearer "+old)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	newHash, err := credential.LoadAdminHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if credential.VerifyAdminPassword(old, newHash) {
		t.Fatal("old password must not verify after reset")
	}
}
