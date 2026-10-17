package httpbody

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func rejectionServer(handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}

func readRejection(t *testing.T, conn net.Conn, reader *bufio.Reader) *http.Response {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("rejection response lost: %v", err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		response.Body.Close()
		t.Fatalf("incomplete response: %v", err)
	}
	response.Body.Close()
	return response
}

func TestDiscardRejectedSmallClosePostsAndChunkedBodiesDeliverActualResponse(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			server := rejectionServer(func(w http.ResponseWriter, r *http.Request) { DiscardRejected(w, r); http.Error(w, "maintenance", 503) })
			defer server.Close()
			for attempt := 0; attempt < 50; attempt++ {
				conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
				if err != nil {
					t.Fatal(err)
				}
				body := "private-fixture-value"
				framing := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
				if chunked {
					framing = fmt.Sprintf("Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
				}
				if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n%s", framing); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				response := readRejection(t, conn, bufio.NewReader(conn))
				conn.Close()
				if response.StatusCode != 503 {
					t.Fatalf("status=%d", response.StatusCode)
				}
			}
		})
	}
}

func TestDiscardRejectedSlowBodyIsBoundedAndClosesConnection(t *testing.T) {
	for _, framing := range []string{"Content-Length: 20", "Transfer-Encoding: chunked"} {
		t.Run(framing, func(t *testing.T) {
			done := make(chan struct{})
			server := rejectionServer(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				DiscardRejected(w, r)
				http.Error(w, "maintenance", 503)
			})
			defer server.Close()
			conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			started := time.Now()
			if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: localhost\r\n%s\r\n\r\n", framing); err != nil {
				t.Fatal(err)
			}
			response := readRejection(t, conn, bufio.NewReader(conn))
			if response.StatusCode != 503 || !response.Close {
				t.Fatalf("slow request status=%d close=%v", response.StatusCode, response.Close)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("slow body held rejected handler")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("slow rejection exceeded its bound")
			}
		})
	}
}

func TestDiscardRejectedLargeOrExpectContinueDoesNotWaitForPayload(t *testing.T) {
	for _, headers := range []string{"Content-Length: 1073741824", "Content-Length: 20\r\nExpect: 100-continue"} {
		t.Run(headers, func(t *testing.T) {
			server := rejectionServer(func(w http.ResponseWriter, r *http.Request) { DiscardRejected(w, r); http.Error(w, "maintenance", 503) })
			defer server.Close()
			conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: localhost\r\n%s\r\n\r\n", headers); err != nil {
				t.Fatal(err)
			}
			response := readRejection(t, conn, bufio.NewReader(conn))
			if response.StatusCode != 503 || !response.Close {
				t.Fatalf("untrusted payload status=%d close=%v", response.StatusCode, response.Close)
			}
		})
	}
}

func TestDiscardRejectedKeepAliveDoesNotPoisonNextRequest(t *testing.T) {
	server := rejectionServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reject" {
			DiscardRejected(w, r)
			http.Error(w, "maintenance", 503)
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "body read failed", 400)
			return
		}
		io.WriteString(w, "ok")
	})
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "POST /reject HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello"); err != nil {
		t.Fatal(err)
	}
	if response := readRejection(t, conn, reader); response.StatusCode != 503 || response.Close {
		t.Fatalf("small reusable rejection: status=%d close=%v", response.StatusCode, response.Close)
	}
	// Exceed our previous temporary read deadline before sending another body.
	time.Sleep(rejectedBodyTimeout + 50*time.Millisecond)
	if _, err := io.WriteString(conn, "POST /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 5\r\n\r\nworld"); err != nil {
		t.Fatal(err)
	}
	if response := readRejection(t, conn, reader); response.StatusCode != 200 {
		t.Fatalf("next request status=%d", response.StatusCode)
	}
}

type deadlineResponse struct {
	*httptest.ResponseRecorder
	last time.Time
}

func (w *deadlineResponse) SetReadDeadline(value time.Time) error { w.last = value; return nil }

type countedBody struct {
	io.Reader
	read int
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *countedBody) Close() error { return nil }

func TestDiscardRejectedUnknownOverflowAndUnsupportedWriterAreBounded(t *testing.T) {
	body := &countedBody{Reader: strings.NewReader(strings.Repeat("x", rejectedBodyLimit+10000))}
	request := httptest.NewRequest("POST", "/", nil)
	request.Body = body
	request.ContentLength = -1
	writer := &deadlineResponse{ResponseRecorder: httptest.NewRecorder()}
	DiscardRejected(writer, request)
	if body.read != rejectedBodyLimit+1 || writer.Header().Get("Connection") != "close" || writer.last.IsZero() {
		t.Fatalf("unknown overflow bytes=%d close=%q", body.read, writer.Header().Get("Connection"))
	}
	for _, kind := range []string{"large", "expect", "unsupported", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			body := &countedBody{Reader: strings.NewReader("never-read-fixture")}
			r := httptest.NewRequest("POST", "/", nil)
			r.Body = body
			r.ContentLength = 18
			w := &deadlineResponse{ResponseRecorder: httptest.NewRecorder()}
			switch kind {
			case "large":
				r.ContentLength = rejectedBodyLimit + 1
			case "expect":
				r.Header.Set("Expect", "100-continue")
			case "canceled":
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			if kind == "unsupported" {
				DiscardRejected(w.ResponseRecorder, r)
			} else {
				DiscardRejected(w, r)
			}
			if body.read != 0 || w.Header().Get("Connection") != "close" {
				t.Fatalf("untrusted body read=%d close=%q", body.read, w.Header().Get("Connection"))
			}
		})
	}
}

type cancelReadBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelReadBody) Read(p []byte) (int, error) { b.cancel(); return b.ReadCloser.Read(p) }

func TestDiscardRejectedCancellationInterruptsSocketRead(t *testing.T) {
	finished := make(chan time.Duration, 1)
	server := rejectionServer(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		r = r.WithContext(ctx)
		r.Body = &cancelReadBody{ReadCloser: r.Body, cancel: cancel}
		started := time.Now()
		DiscardRejected(w, r)
		finished <- time.Since(started)
		http.Error(w, "maintenance", 503)
	})
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if response := readRejection(t, conn, bufio.NewReader(conn)); response.StatusCode != 503 || !response.Close {
		t.Fatalf("canceled status=%d close=%v", response.StatusCode, response.Close)
	}
	select {
	case elapsed := <-finished:
		if elapsed > time.Second {
			t.Fatalf("cancel took %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not finish handler")
	}
}

func TestDiscardRejectedClearsItsSuccessfulReadDeadline(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("fixture-small-body"))
	w := &deadlineResponse{ResponseRecorder: httptest.NewRecorder()}
	DiscardRejected(w, r)
	if !w.last.IsZero() || w.Header().Get("Connection") != "" {
		t.Fatal("successful discard retained a deadline or forced connection close")
	}
}
