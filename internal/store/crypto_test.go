package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{
		"sk-abc123",
		"",
		strings.Repeat("x", 4096),
		"含中文与 emoji 🔑 的 key",
	} {
		enc, err := c.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if enc == plain && plain != "" {
			t.Fatal("密文不应等于明文")
		}
		got, err := c.Decrypt(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got != plain {
			t.Fatalf("往返不一致：want %q got %q", plain, got)
		}
	}
}

// GCM 下 nonce 复用会泄露明文异或值，所以每次加密都必须用新 nonce。
// 表现为：同一明文两次加密的密文必须不同。
func TestEncryptUsesFreshNonce(t *testing.T) {
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	a, _ := c.Encrypt("sk-same-input")
	b, _ := c.Encrypt("sk-same-input")
	if a == b {
		t.Fatal("同一明文两次加密的密文相同 —— nonce 被复用了，这会泄露明文")
	}
}

// 换了 ENCRYPTION_KEY 后必须解密失败并明确指出原因，
// 而不是静默返回垃圾 key（那会表现为上游 401，把人引向错误的排查方向）。
func TestDecryptWithWrongKeyFails(t *testing.T) {
	c1, _ := NewCipher("passphrase-number-one-1234567890")
	c2, _ := NewCipher("passphrase-number-two-0987654321")

	enc, err := c1.Encrypt("sk-secret")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c2.Decrypt(enc)
	if err == nil {
		t.Fatalf("换密钥后应解密失败，却返回了 %q", got)
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Errorf("错误信息应提示 ENCRYPTION_KEY 不一致，得到：%v", err)
	}
}

// 密文被篡改必须失败（GCM 的完整性校验）。
func TestDecryptDetectsTampering(t *testing.T) {
	c, _ := NewCipher("test-passphrase-at-least-16-chars")
	enc, _ := c.Encrypt("sk-secret-value")

	b := []byte(enc)
	// 改最后一个字符（base64 尾部，落在密文/tag 上）
	if b[len(b)-2] == 'A' {
		b[len(b)-2] = 'B'
	} else {
		b[len(b)-2] = 'A'
	}
	if _, err := c.Decrypt(string(b)); err == nil {
		t.Fatal("被篡改的密文应解密失败")
	}
}

func TestNewCipherRejectsEmpty(t *testing.T) {
	for _, s := range []string{"", "   ", "\t\n"} {
		if _, err := NewCipher(s); err == nil {
			t.Fatalf("空口令 %q 应被拒绝", s)
		}
	}
}

// MaskKey 用在 API 回显与样本记录里。短 key 必须全打码 ——
// 留前后各 4 位对一个 12 字符的 key 等于泄露 2/3。
func TestMaskKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"sk-1234567890abcdef", "sk-1…cdef"},
		{"short", "*****"},
		{"sk-12345678", "***********"}, // 11 字符 < 4*2+6，全打码
	}
	for _, c := range cases {
		if got := MaskKey(c.in); got != c.want {
			t.Errorf("MaskKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// 核心保证：脱敏结果里不得出现完整的原 key
	long := "sk-ThisIsAVeryLongSecretKeyValue123456"
	if m := MaskKey(long); strings.Contains(m, long) {
		t.Errorf("脱敏结果 %q 仍含完整 key", m)
	}
}

func TestCipherDomainSeparatedFingerprints(t *testing.T) {
	c, err := NewCipher("manifest-key-test")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.KeyID(), "211a8cd1e88bfe28"; got != want {
		t.Fatalf("KeyID = %q, want %q", got, want)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "probe secret",
			got:  c.Fingerprint("probe-secret", []byte("abc")),
			want: "211a8cd1e88bfe28:52ce1a1ecdf2c2d1270d2612a4053412291016fc7ced18821b7b95dde540cc37",
		},
		{
			name: "legacy full URL",
			got:  c.Fingerprint("legacy-full-url", []byte("abc")),
			want: "211a8cd1e88bfe28:1d217f77274f06a832edf25b7061cd19802009a2ffd29fe48916277791cbf0d8",
		},
		{
			name: "request URL",
			got:  c.SumRequestURL([]byte("https://example.com/v1/messages?a=1")),
			want: "211a8cd1e88bfe28:c49e64d5e749fa1216a32f823dacf059493a5c9898d79b463aaf0294a9532deb",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("digest = %q, want golden %q", tc.got, tc.want)
			}
		})
	}

	raw := sha256.Sum256([]byte("abc"))
	rawHex := hex.EncodeToString(raw[:])
	if strings.Contains(tests[0].got, rawHex) || tests[0].got == tests[1].got {
		t.Fatal("fingerprint must be keyed and domain-separated")
	}
}
