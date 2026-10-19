package proxy

import (
	"context"
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
		if s.FirstEventAt.IsZero() {
			s.FirstEventAt = at
			changed = true
		}
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
	at.res.FirstEventAt = s.FirstEventAt
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
	finished := make(chan struct{})
	closer, sentAt, status := at.resp.Body, at.res.SentAt, at.resp.StatusCode
	go func() {
		defer close(finished)
		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		changes := at.wire.changes
		var async <-chan struct{}
		if at.wire.async != nil {
			async = at.wire.async.ProgressChanges()
		}
		for {
			s := at.wire.snapshot()
			firstByte, lastByte := at.wire.firstByte.Load(), at.wire.lastByte.Load()
			var first, last time.Time
			if firstByte != 0 {
				first = time.Unix(0, firstByte)
			}
			if lastByte != 0 {
				last = time.Unix(0, lastByte)
			}
			deadline, kind := at.f.Timeouts.pendingDeadline(sentAt, true, first, s.FirstSemanticAt, last, s.Incomplete != "", status)
			var expired <-chan time.Time
			if !deadline.IsZero() {
				delay := time.Until(deadline)
				if delay < 0 {
					delay = 0
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
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
				var currentFirst, currentLast time.Time
				if value := at.wire.firstByte.Load(); value != 0 {
					currentFirst = time.Unix(0, value)
				}
				if value := at.wire.lastByte.Load(); value != 0 {
					currentLast = time.Unix(0, value)
				}
				currentDeadline, currentKind := at.f.Timeouts.pendingDeadline(sentAt, true, currentFirst, now.FirstSemanticAt, currentLast, now.Incomplete != "", status)
				if currentKind != kind || currentDeadline.After(deadline) || time.Now().Before(currentDeadline) {
					continue
				}
				at.stageTimeout.Store(kind)
				if at.cancel != nil {
					at.cancel()
				}
				_ = closer.Close()
				return
			}
		}
	}()
	return func() { close(done); <-finished }
}

func (at *Attempt) readFailure(err error, total int64) error {
	if at.clientCtx.Err() != nil {
		if errors.Is(context.Cause(at.clientCtx), ErrTotalTimeout) {
			return ErrTotalTimeout
		}
		return ErrCanceled
	}
	if kind := at.stageTimeout.Load(); kind != 0 {
		return responseStageError(kind)
	}
	if at.ctx.Err() != nil {
		return ErrTotalTimeout
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	if total == 0 {
		return ErrUpstreamBroke
	}
	return ErrStreamBroke
}
