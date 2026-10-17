package api

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type rejectedEOFBody struct {
	io.ReadCloser
	once sync.Once
	eof  chan struct{}
}

func (b *rejectedEOFBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(func() { close(b.eof) })
	}
	return n, err
}

func TestFrozenAdminSmallConnectionClosePostIsConsumedBeforeFinalResponse(t *testing.T) {
	s := &Server{}
	s.mutations.closed = true
	eof := make(chan struct{})
	frozen := s.guardMutations(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("frozen request reached mutation handler") }))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = &rejectedEOFBody{ReadCloser: r.Body, eof: eof}
		frozen.ServeHTTP(w, r)
	}))
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"fixture","value":"private-fixture-not-to-be-retained"}`
	if _, err := fmt.Fprintf(conn, "POST /admin/api/probe-secrets HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("small rejected POST lost its real 409 response: %v", err)
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("incomplete rejection response: %v", err)
	}
	if response.StatusCode != 409 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if strings.Contains(string(wire), "private-fixture") {
		t.Fatal("rejection leaked discarded body")
	}
	select {
	case <-eof:
	default:
		t.Fatal("small Connection:close POST was closed with unread body; Windows can discard the final response with TCP reset")
	}
}
