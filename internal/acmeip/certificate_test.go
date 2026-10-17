package acmeip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testCertificate(t *testing.T, ip string, lifetime time.Duration) (string, string, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(300 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootParsed, _ := x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), IPAddresses: []net.IP{net.ParseIP(ip)}, Subject: pkix.Name{CommonName: ip}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, rootParsed, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err := os.WriteFile(certPath, chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootParsed)
	return certPath, keyPath, roots
}

func TestPublicCertificateValidationFailsClosed(t *testing.T) {
	cert, key, roots := testCertificate(t, "8.8.8.8", 160*time.Hour)
	if _, err := ValidateCertificateFiles(cert, key, "8.8.8.8", roots, time.Now(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateCertificateFiles(cert, key, "9.9.9.9", roots, time.Now(), 24*time.Hour); err == nil {
		t.Fatal("wrong IP SAN accepted")
	}
	if _, err := ValidateCertificateFiles(cert, key, "8.8.8.8", x509.NewCertPool(), time.Now(), 24*time.Hour); err == nil {
		t.Fatal("untrusted chain accepted")
	}
	short, shortKey, shortRoots := testCertificate(t, "8.8.8.8", time.Hour)
	if _, err := ValidateCertificateFiles(short, shortKey, "8.8.8.8", shortRoots, time.Now(), 24*time.Hour); err == nil {
		t.Fatal("near-expiry initial certificate accepted")
	}
	long, longKey, longRoots := testCertificate(t, "8.8.8.8", 90*24*time.Hour)
	if _, err := ValidateCertificateFiles(long, longKey, "8.8.8.8", longRoots, time.Now(), 24*time.Hour); err == nil {
		t.Fatal("non-shortlived certificate accepted")
	}
	if _, err := ValidateCertificateFiles(cert, shortKey, "8.8.8.8", roots, time.Now(), 24*time.Hour); err == nil {
		t.Fatal("certificate/private-key mismatch accepted")
	}
	if runtime.GOOS != "windows" {
		os.Chmod(key, 0644)
		if _, err := ValidateCertificateFiles(cert, key, "8.8.8.8", roots, time.Now(), 24*time.Hour); err == nil {
			t.Fatal("world-readable private key accepted")
		}
	}
}

func TestPublicIPValidationRejectsNonPublicTargets(t *testing.T) {
	for _, ip := range []string{"", "example.com", "127.0.0.1", "10.0.0.1", "192.168.1.1", "100.64.0.1", "203.0.113.1", "198.51.100.1", "0.0.0.0", "::", "::1", "fc00::1", "2001:db8::1", "8.8.8.8;echo x"} {
		if _, err := ParsePublicIP(ip); err == nil {
			t.Errorf("non-public/invalid target accepted: %q", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if _, err := ParsePublicIP(ip); err != nil {
			t.Fatal(err)
		}
	}
}
