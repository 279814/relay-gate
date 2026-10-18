package security

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSMTPRequiresOneTLSModeBeforeSending(t *testing.T) {
	for _, modes := range []struct {
		name            string
		startTLS, smtps bool
	}{
		{"required_STARTTLS_not_advertised", true, false},
		{"missing_mode", false, false},
		{"conflicting_modes", true, true},
	} {
		t.Run(modes.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var sent atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(connection)
				fmt.Fprint(connection, "220 fixture SMTP\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
						fmt.Fprint(connection, "250 fixture\r\n")
					case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						sent.Add(1)
						fmt.Fprint(connection, "250 OK\r\n")
					case strings.HasPrefix(line, "DATA"):
						fmt.Fprint(connection, "354 continue\r\n")
						for {
							data, err := reader.ReadString('\n')
							if err != nil {
								return
							}
							if data == ".\r\n" {
								break
							}
						}
						fmt.Fprint(connection, "250 accepted\r\n")
					case strings.HasPrefix(line, "QUIT"):
						fmt.Fprint(connection, "221 bye\r\n")
						return
					default:
						fmt.Fprint(connection, "250 OK\r\n")
					}
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			mailer := NewAlertMailer()
			mailer.SetConfig(MailConfig{Enabled: true, Host: host, Port: smtpTestPort(port), UseSTARTTLS: modes.startTLS,
				UseSMTPS: modes.smtps, From: "relay@example.test", Recipients: []string{"ops@example.test"}})
			if err := mailer.SendTest(""); err == nil {
				t.Error("SMTP transport accepted plaintext or an invalid TLS mode")
			}
			listener.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("SMTP connection was not released")
			}
			if sent.Load() != 0 {
				t.Fatalf("sent %d envelope commands before required TLS", sent.Load())
			}
		})
	}
}

func TestSMTPManualTestDeliversOnceEvenWhenAlertsDisabled(t *testing.T) {
	calls := 0
	mailer := NewAlertMailer().WithSendForTest(func(string, smtp.Auth, string, []string, []byte) error { calls++; return nil })
	mailer.SetConfig(MailConfig{Enabled: false, Host: "smtp.example.test", Port: 587, UseSTARTTLS: true,
		From: "relay@example.test", Recipients: []string{"ops@example.test"}})
	for i := 0; i < 2; i++ {
		if err := mailer.SendTest(""); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("manual tests reported success but delivered %d of 2 messages", calls)
	}
}

func smtpTestPort(port string) int {
	var value int
	fmt.Sscanf(port, "%d", &value)
	return value
}

func TestSMTPRealTLSDelivery(t *testing.T) {
	for _, smtps := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit_TLS_%t", smtps), func(t *testing.T) {
			server := startTLSMailFixture(t, smtps, false)
			mailer := NewAlertMailer()
			mailer.tlsConfig = &tls.Config{RootCAs: server.roots}
			mailer.SetConfig(server.config())
			if err := mailer.SendTest("https://admin.example.test/admin/"); err != nil {
				t.Fatalf("verified TLS SMTP delivery failed: %v", err)
			}
			select {
			case message := <-server.messages:
				if !strings.Contains(message, "source: smtp_test") || !strings.Contains(message, "metadata only") {
					t.Fatal("actual SMTP DATA omitted expected metadata")
				}
				if strings.Contains(message, "fixture-mail-password") {
					t.Fatal("SMTP password entered message data")
				}
			case <-time.After(time.Second):
				t.Fatal("successful send did not reach SMTP DATA")
			}
			if !server.authenticated.Load() || server.plaintextEnvelope.Load() {
				t.Fatal("authentication or envelope did not use verified TLS")
			}
		})
	}
}

func TestSMTPRejectsUntrustedTLSBeforeAuthentication(t *testing.T) {
	for _, smtps := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit_TLS_%t", smtps), func(t *testing.T) {
			server := startTLSMailFixture(t, smtps, false)
			mailer := NewAlertMailer()
			mailer.SetConfig(server.config())
			if err := mailer.SendTest(""); err == nil {
				t.Fatal("untrusted certificate was accepted")
			}
			if server.authenticated.Load() || server.plaintextEnvelope.Load() {
				t.Fatal("credentials or envelope sent before certificate verification")
			}
		})
	}
}

func TestSMTPChecksConfiguredHostnameBeforeAuthentication(t *testing.T) {
	server := startTLSMailFixture(t, false, false)
	mailer := NewAlertMailer()
	mailer.tlsConfig = &tls.Config{RootCAs: server.roots}
	mailer.dial = func(string) (net.Conn, error) { return net.DialTimeout("tcp", server.address, time.Second) }
	config := server.config()
	config.Host = "wrong-host.example.test"
	mailer.SetConfig(config)
	var hostnameError x509.HostnameError
	if err := mailer.SendTest(""); !errors.As(err, &hostnameError) {
		t.Fatalf("configured hostname was not verified: %T", err)
	}
	if server.authenticated.Load() || server.plaintextEnvelope.Load() {
		t.Fatal("authentication or envelope preceded hostname verification")
	}
}

func TestSMTPUsesOneDeadlineForSilentServer(t *testing.T) {
	server := startTLSMailFixture(t, false, true)
	mailer := NewAlertMailer()
	mailer.timeout = 50 * time.Millisecond
	mailer.SetConfig(server.config())
	started := time.Now()
	if err := mailer.SendTest(""); err == nil {
		t.Fatal("silent SMTP server returned success")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatalf("SMTP exchange escaped its deadline: %v", time.Since(started))
	}
}

type tlsMailFixture struct {
	address           string
	implicit          bool
	roots             *x509.CertPool
	messages          chan string
	authenticated     atomic.Bool
	plaintextEnvelope atomic.Bool
}

func (server *tlsMailFixture) config() MailConfig {
	host, port, _ := net.SplitHostPort(server.address)
	return MailConfig{Enabled: true, Host: host, Port: smtpTestPort(port), UseSMTPS: server.implicit,
		UseSTARTTLS: !server.implicit, From: "relay@example.test", Recipients: []string{"ops@example.test"},
		Username: "fixture-user", Password: "fixture-mail-password"}
}

func startTLSMailFixture(t *testing.T, implicit, silent bool) *tlsMailFixture {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{encoded}, PrivateKey: privateKey}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &tlsMailFixture{address: listener.Addr().String(), implicit: implicit, roots: roots, messages: make(chan string, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		if silent {
			io.Copy(io.Discard, connection)
			return
		}
		var reader *bufio.Reader
		encrypted := false
		secure := func() bool {
			secured := tls.Server(connection, config)
			if err := secured.Handshake(); err != nil {
				return false
			}
			connection = secured
			reader = bufio.NewReader(secured)
			encrypted = true
			return true
		}
		if implicit && !secure() {
			return
		}
		reader = bufio.NewReader(connection)
		fmt.Fprint(connection, "220 SMTP fixture\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				if encrypted {
					fmt.Fprint(connection, "250-fixture\r\n250 AUTH PLAIN\r\n")
				} else {
					fmt.Fprint(connection, "250-fixture\r\n250 STARTTLS\r\n")
				}
			case strings.HasPrefix(line, "STARTTLS"):
				fmt.Fprint(connection, "220 begin TLS\r\n")
				if !secure() {
					return
				}
			case strings.HasPrefix(line, "AUTH PLAIN"):
				if !encrypted {
					server.plaintextEnvelope.Store(true)
					return
				}
				parts := strings.Fields(line)
				if len(parts) != 3 {
					return
				}
				credentials, err := base64.StdEncoding.DecodeString(parts[2])
				if err != nil || string(credentials) != "\x00fixture-user\x00fixture-mail-password" {
					return
				}
				server.authenticated.Store(true)
				fmt.Fprint(connection, "235 authenticated\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				if !encrypted {
					server.plaintextEnvelope.Store(true)
				}
				fmt.Fprint(connection, "250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				if !encrypted {
					server.plaintextEnvelope.Store(true)
				}
				fmt.Fprint(connection, "354 continue\r\n")
				message, err := io.ReadAll(io.LimitReader(textproto.NewReader(reader).DotReader(), 1<<20))
				if err != nil {
					return
				}
				server.messages <- string(message)
				fmt.Fprint(connection, "250 accepted\r\n")
			case strings.HasPrefix(line, "QUIT"):
				fmt.Fprint(connection, "221 bye\r\n")
				return
			default:
				fmt.Fprint(connection, "250 OK\r\n")
			}
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SMTP fixture did not release its connection")
		}
	})
	return server
}
