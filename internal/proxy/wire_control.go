package proxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/protocol"
)

const controlEventLimit = 64 << 10
const controlInputLimit = 256 << 10

// wireEvidence contains facts only. It never retains response/error text and
// never decides retry or health. Identity input uses the shared Decoder after
// flush; encoded input reads the existing bounded observer worker's progress.
type wireEvidence struct {
	decoder   protocol.Decoder
	async     health.AttemptResponseProgress
	state     atomic.Pointer[health.ResponseProgress]
	firstByte atomic.Int64
	lastByte  atomic.Int64
	changes   chan struct{}
	finished  bool
}

func newWireEvidence(proto model.Protocol, header http.Header, observer health.AttemptObserver) *wireEvidence {
	w := &wireEvidence{changes: make(chan struct{}, 1)}
	encoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		w.async, _ = observer.(health.AttemptResponseProgress)
		if w.async == nil {
			w.fail(model.ObserverPrepareFailure)
		}
		return w
	}
	endpoint, _ := proto.Endpoint()
	var err error
	w.decoder, err = protocol.NewDecoder(protocol.DecoderSpec{Endpoint: endpoint, Protocol: proto}, protocol.WireAuto, controlEventLimit, controlInputLimit)
	if err != nil {
		w.fail(model.ObserverPrepareFailure)
	}
	return w
}

func (w *wireEvidence) notify() {
	select {
	case w.changes <- struct{}{}:
	default:
	}
}
func (w *wireEvidence) fail(reason model.ObserverIncompleteReason) {
	s := w.snapshot()
	s.Incomplete = reason
	w.state.Store(&s)
	w.notify()
}
func (w *wireEvidence) snapshot() (state health.ResponseProgress) {
	if w == nil {
		state.Incomplete = model.ObserverPrepareFailure
		return
	}
	if state := w.state.Load(); state != nil && state.Incomplete != "" {
		return *state
	}
	if w.async != nil {
		defer func() {
			if recover() != nil {
				state.Incomplete = model.ObserverPanic
			}
		}()
		return w.async.ResponseProgress()
	}
	if s := w.state.Load(); s != nil {
		return *s
	}
	return
}
func (w *wireEvidence) accept(events []protocol.ProtocolEvent, at time.Time) {
	s := w.snapshot()
	changed := false
	for _, event := range events {
		if event.Semantic {
			changed = true
			if s.FirstSemanticAt.IsZero() {
				s.FirstSemanticAt = at
			}
			s.LastSemanticAt = at
		}
	}
	if changed {
		w.state.Store(&s)
	}
}
func (w *wireEvidence) feed(body []byte, at time.Time) {
	if w == nil || len(body) == 0 {
		return
	}
	w.firstByte.CompareAndSwap(0, at.UnixNano())
	w.lastByte.Store(at.UnixNano())
	defer w.notify()
	if w.decoder == nil || w.finished || w.snapshot().Incomplete != "" {
		return
	}
	events, err := w.decoder.Feed(body)
	w.accept(events, at)
	if err != nil {
		reason := model.ObserverDecodeFailure
		if errors.Is(err, protocol.ErrEventTooLarge) || errors.Is(err, protocol.ErrDecodedBodyTooLarge) || errors.Is(err, protocol.ErrDecoderWorkBudget) {
			reason = model.ObserverInputLimit
		}
		w.fail(reason)
	}
}
func (w *wireEvidence) finish() {
	if w == nil || w.decoder == nil || w.finished {
		return
	}
	w.finished = true
	if w.snapshot().Incomplete != "" {
		return
	}
	events, err := w.decoder.Finish()
	w.accept(events, time.Unix(0, w.lastByte.Load()))
	if err != nil {
		w.fail(model.ObserverDecodeFailure)
	}
	w.notify()
}
func (at *Attempt) projectWire() {
	if at.wire == nil {
		return
	}
	s := at.wire.snapshot()
	at.res.ObserverIncomplete = s.Incomplete
	if at.res.FirstByteAt.IsZero() && at.wire.firstByte.Load() != 0 {
		at.res.FirstByteAt = time.Unix(0, at.wire.firstByte.Load())
	}
	if !s.FirstSemanticAt.IsZero() && at.resp.StatusCode >= 200 && at.resp.StatusCode < 400 {
		at.res.SemanticSeen = true
		if at.res.FirstSemanticAt.IsZero() {
			at.res.FirstSemanticAt = s.FirstSemanticAt
			if at.f.OnFirstByte != nil {
				at.f.OnFirstByte()
			}
		}
	}
}

// One existing cancellation watcher also owns the stage timer. First semantic
// enables Idle; subsequent original upstream activity resets it, including
// keepalives. Transformed output cannot refresh it. Capacity/codec failures fall
// back to the outer total deadline after first byte.
func (at *Attempt) watchResponse() func() {
	if at.wire == nil {
		at.wire = newWireEvidence(at.f.Protocol, at.res.RespHeaders, at.f.RespObserver)
	}
	done := make(chan struct{})
	closer, sentAt, status := at.resp.Body, at.res.SentAt, at.resp.StatusCode
	go func() {
		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		changes := at.wire.changes
		var async <-chan struct{}
		if at.wire.async != nil {
			async = at.wire.async.ProgressChanges()
		}
		for {
			s := at.wire.snapshot()
			deadline, kind := sentAt.Add(at.f.Timeouts.FirstToken), int32(1)
			lastByte := at.wire.lastByte.Load()
			if lastByte != 0 {
				if s.Incomplete != "" {
					deadline = time.Time{}
				} else if status >= 400 {
					deadline = time.Unix(0, lastByte).Add(at.f.Timeouts.Idle)
					kind = 2
				} else if !s.LastSemanticAt.IsZero() {
					deadline = time.Unix(0, lastByte).Add(at.f.Timeouts.Idle)
					kind = 2
				}
			}
			var expired <-chan time.Time
			if !deadline.IsZero() {
				delay := time.Until(deadline)
				if delay < 0 {
					delay = 0
				}
				timer.Reset(delay)
				expired = timer.C
			} else {
				timer.Stop()
			}
			select {
			case <-done:
				return
			case <-at.ctx.Done():
				_ = closer.Close()
				return
			case <-changes:
				continue
			case _, open := <-async:
				if !open {
					async = nil
					at.wire.fail(model.ObserverPrepareFailure)
				}
				continue
			case <-expired:
				// A progress notification can race the timer; recompute before
				// closing when reliable new evidence has extended the deadline.
				now := at.wire.snapshot()
				if at.wire.lastByte.Load() != 0 && (now.Incomplete != "" || now.LastSemanticAt.After(s.LastSemanticAt) || ((status >= 400 || !now.LastSemanticAt.IsZero()) && at.wire.lastByte.Load() > lastByte)) {
					continue
				}
				at.stageTimeout.Store(kind)
				_ = closer.Close()
				return
			}
		}
	}()
	return func() { close(done) }
}

func (at *Attempt) readFailure(err error, total int64) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	if at.clientCtx.Err() != nil {
		return ErrCanceled
	}
	if at.ctx.Err() != nil {
		return ErrTotalTimeout
	}
	switch at.stageTimeout.Load() {
	case 1:
		return ErrFirstTokenTimeout
	case 2:
		return ErrStreamStalled
	}
	if total == 0 {
		return ErrUpstreamBroke
	}
	return ErrStreamBroke
}
