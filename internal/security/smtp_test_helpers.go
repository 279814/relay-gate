package security

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// StartFakeSMTP starts a minimal SMTP listener for tests. Returns addr and captured messages.
func StartFakeSMTP(t *testing.T) (addr string, messages *[]string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var msgs []string
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go handleFakeSMTP(c, &mu, &msgs)
		}
	}()
	closeFn = func() {
		close(done)
		_ = ln.Close()
	}
	return ln.Addr().String(), &msgs, closeFn
}

func handleFakeSMTP(c net.Conn, mu *sync.Mutex, msgs *[]string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	write := func(s string) {
		_, _ = bw.WriteString(s + "\r\n")
		_ = bw.Flush()
	}
	write("220 fake.smtp ESMTP")
	var data strings.Builder
	inData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if inData {
				mu.Lock()
				*msgs = append(*msgs, data.String())
				mu.Unlock()
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				mu.Lock()
				*msgs = append(*msgs, data.String())
				mu.Unlock()
				inData = false
				data.Reset()
				write("250 OK")
				continue
			}
			data.WriteString(line)
			data.WriteByte('\n')
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250-fake")
			write("250 OK")
		case strings.HasPrefix(upper, "MAIL"), strings.HasPrefix(upper, "RCPT"):
			write("250 OK")
		case strings.HasPrefix(upper, "DATA"):
			write("354 End data with <CR><LF>.<CR><LF>")
			inData = true
		case strings.HasPrefix(upper, "QUIT"):
			write("221 Bye")
			return
		case strings.HasPrefix(upper, "RSET"), strings.HasPrefix(upper, "NOOP"):
			write("250 OK")
		default:
			write("250 OK")
		}
	}
}

// CaptureSend returns a send func that records the message and optionally dials fake SMTP.
func CaptureSend(captured *[]string) func(addr string, a interface{}, from string, to []string, msg []byte) error {
	return func(addr string, _ interface{}, from string, to []string, msg []byte) error {
		*captured = append(*captured, string(msg))
		if len(to) == 0 || from == "" {
			return fmt.Errorf("missing from/to")
		}
		// Ensure we could open TCP to addr (fake SMTP is up).
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(c, "")
		_ = c.Close()
		return nil
	}
}
