package security

import (
	"fmt"
	"strings"
	"testing"
)

func repeatedPrefixCredentials() []string {
	keys := make([]string, 64)
	for i := range keys {
		keys[i] = strings.Repeat("a", 4094) + fmt.Sprintf("%02d", i)
	}
	return keys
}

func TestUnicodeEscapedCredentialOverlappingPrefixesAndMixedHex(t *testing.T) {
	key := "aaaaaaab-long-synthetic"
	escaped := jsonByteUnicodeEscape(key)
	body := strings.Repeat(`\u0061`, 5000) + escaped + " marker " + jsonUnicodeEscapeUpperHex(escaped) + " trailing"
	want := strings.Repeat(`\u0061`, 5000) + maskSecret(key) + " marker " + maskSecret(key) + " trailing"
	if got := RedactSecrets(body, []string{key}); got != want {
		t.Fatal("Unicode escaped replacement changed overlap, hex-case or surrounding bytes")
	}
	if got := RedactSecrets(escaped+jsonUnicodeEscapeUpperHex(escaped), []string{key}); got != maskSecret(key)+maskSecret(key) {
		t.Fatal("adjacent escaped matches changed")
	}
	repeated := strings.Repeat("a", 16)
	if got := RedactSecrets(strings.Repeat(`\u0061`, 20), []string{repeated}); got != maskSecret(repeated)+strings.Repeat(`\u0061`, 4) {
		t.Fatal("overlapping escaped matches changed ReplaceAll semantics")
	}
}

func BenchmarkRedactKnownCredentialRepeatedEscapedPrefix(b *testing.B) {
	keys := repeatedPrefixCredentials()
	body := strings.Repeat(`\u0061`, 5400)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RedactSecrets(body, keys)
	}
}
