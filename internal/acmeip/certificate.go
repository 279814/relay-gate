package acmeip

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"
)

const maximumIPCertificateLifetime = 192 * time.Hour

type CertificateInfo struct {
	NotAfter    time.Time
	Fingerprint string
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
}

func ParsePublicIP(value string) (netip.Addr, error) {
	if strings.TrimSpace(value) != value {
		return netip.Addr{}, errors.New("公网 IP 含空白")
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, errors.New("必须提供一个公网 IPv4/IPv6 地址")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("必须使用可路由公网 IP")
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return netip.Addr{}, errors.New("IPv6 不是受支持的全球单播地址")
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return netip.Addr{}, errors.New("保留/文档地址不能作为公网签发目标")
		}
	}
	return ip, nil
}

func readCertificateFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("证书文件超过合理大小")
	}
	return raw, nil
}

// ValidateCertificateFiles uses the system trust store in production. A roots
// pool is injectable for isolated local-CA tests, never exposed by the CLI.
func ValidateCertificateFiles(certPath, keyPath, expectIP string, roots *x509.CertPool, now time.Time, minRemaining time.Duration) (CertificateInfo, error) {
	var info CertificateInfo
	ip, err := ParsePublicIP(expectIP)
	if err != nil {
		return info, err
	}
	keyStat, err := os.Stat(keyPath)
	if err != nil {
		return info, err
	}
	if !keyStat.Mode().IsRegular() {
		return info, errors.New("私钥不是普通文件")
	}
	if runtime.GOOS != "windows" && keyStat.Mode().Perm()&0077 != 0 {
		return info, errors.New("私钥必须仅属主可读写")
	}
	certPEM, err := readCertificateFile(certPath, 1<<20)
	if err != nil {
		return info, err
	}
	keyPEM, err := readCertificateFile(keyPath, 64<<10)
	if err != nil {
		return info, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return info, errors.New("证书与私钥无法配对")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return info, errors.New("证书格式无效")
	}
	if leaf.IsCA || !now.Before(leaf.NotAfter) || leaf.NotAfter.Sub(now) < minRemaining || leaf.NotAfter.Sub(leaf.NotBefore) > maximumIPCertificateLifetime {
		return info, errors.New("IP 证书剩余效期或短期 profile 不符合要求")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return info, errors.New("证书链格式无效")
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: ip.String(), Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return info, fmt.Errorf("IP SAN 或公网信任链校验失败: %w", err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	return CertificateInfo{NotAfter: leaf.NotAfter, Fingerprint: hex.EncodeToString(fingerprint[:])}, nil
}
