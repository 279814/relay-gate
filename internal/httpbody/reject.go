// Package httpbody contains bounded handling of bodies on early HTTP rejection.
package httpbody

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

const rejectedBodyLimit = 64 << 10
const rejectedBodyTimeout = 200 * time.Millisecond

// DiscardRejected consumes a small request before its final rejection response.
// In particular, net/http does not do this for Connection: close requests and
// closing a socket with unread data can turn the response into a TCP reset.
// Body bytes are discarded without parsing, saving, or logging them. Untrusted
// slow/large bodies cannot hold admission or rotation indefinitely.
func DiscardRejected(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return
	}
	controller := http.NewResponseController(w)
	closeConnection := func() {
		w.Header().Set("Connection", "close")
		// Prevent net/http's final body Close from waiting on more socket data.
		_ = controller.SetReadDeadline(time.Now())
	}
	if r.ContentLength > rejectedBodyLimit || r.Context().Err() != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("Expect")), "100-continue") {
		closeConnection()
		return
	}
	deadline := time.Now().Add(rejectedBodyTimeout)
	if requestDeadline, ok := r.Context().Deadline(); ok && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	if err := controller.SetReadDeadline(deadline); err != nil {
		// A writer without deadline support cannot promise a bounded read.
		closeConnection()
		return
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(r.Context(), func() {
		_ = controller.SetReadDeadline(time.Now())
		close(canceled)
	})
	_, err := io.CopyN(io.Discard, r.Body, rejectedBodyLimit+1)
	// Join an already running cancellation callback before resetting our read
	// deadline; otherwise it could poison the next keep-alive request.
	if !stop() {
		<-canceled
	}
	if err == io.EOF && r.Context().Err() == nil {
		if err := controller.SetReadDeadline(time.Time{}); err == nil {
			return
		}
	}
	closeConnection()
}
