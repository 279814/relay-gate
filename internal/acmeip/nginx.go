package acmeip

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func nginxQuoted(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}

func renderNginx(options PublicOptions, paths *CertificatePaths) string {
	config := fmt.Sprintf("user nginx;\npid %s;\nerror_log /dev/stderr crit;\nevents { worker_connections 1024; }\nhttp {\naccess_log off;\nserver_tokens off;\ngzip off;\nclient_max_body_size 32m;\nserver {\nlisten 80;\nlisten [::]:80;\nserver_name _;\nlocation ^~ /.well-known/acme-challenge/ { root %s; default_type text/plain; try_files $uri =404; limit_except GET HEAD { deny all; } }\n", nginxQuoted(filepath.Join(options.StateDir, "nginx", "nginx.pid")), nginxQuoted(options.Webroot))
	if paths == nil {
		return config + "location / { return 503; }\n}\n}\n"
	}
	ip := options.IP
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	config += fmt.Sprintf("location / { return 308 https://%s$request_uri; }\n}\nserver {\nlisten 443 ssl;\nlisten [::]:443 ssl;\nserver_name _;\nssl_certificate %s;\nssl_certificate_key %s;\nssl_protocols TLSv1.2 TLSv1.3;\nlocation / {\nproxy_pass %s;\nproxy_http_version 1.1;\nproxy_buffering off;\nproxy_request_buffering off;\nproxy_read_timeout 35m;\nproxy_send_timeout 35m;\nsend_timeout 35m;\nproxy_set_header Host $http_host;\nproxy_set_header Connection \"\";\nproxy_set_header X-Forwarded-For $remote_addr;\nproxy_set_header X-Real-IP $remote_addr;\nproxy_set_header X-Forwarded-Proto https;\nproxy_set_header Forwarded \"\";\nproxy_set_header X-Forwarded-Host \"\";\nproxy_set_header X-Forwarded-Port \"\";\n}\n}\n}\n", ip, nginxQuoted(paths.Certificate), nginxQuoted(paths.Key), options.Upstream)
	return config
}

func probeHTTPS(ctx context.Context, address, expectIP, fingerprint string, roots *x509.CertPool) error {
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{ServerName: expectIP, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("本机 HTTPS 握手或信任链验证失败")
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("HTTPS 握手未建立 TLS")
	}
	peer := tlsConn.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		return errors.New("HTTPS 未提供证书")
	}
	sum := sha256.Sum256(peer[0].Raw)
	if hex.EncodeToString(sum[:]) != fingerprint {
		return errors.New("Nginx 尚未加载预期证书")
	}
	return nil
}

func probeChallenge(ctx context.Context, webroot, ip, address string) error {
	folder := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(folder, 0755); err != nil {
		return err
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	name := "relay-preflight-" + hex.EncodeToString(token[:])
	want := "relay-gate:" + name
	file := filepath.Join(folder, name)
	if err := os.WriteFile(file, []byte(want), 0644); err != nil {
		return err
	}
	defer os.Remove(file)
	host := ip
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/.well-known/acme-challenge/"+name, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("无法从确认的公网 IP 回读 ACME 握手；检查路由、80 端口及 NAT 回环")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(len(want)+1)))
	if err != nil || response.StatusCode != 200 || string(raw) != want {
		return errors.New("公网 IP 未指向本机 ACME webroot；业务保持关闭")
	}
	return nil
}
