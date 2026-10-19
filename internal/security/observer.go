package security

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/protocol"
)

const (
	ScannerVersion = "3" // namespaced rule identities survive bounded aggregation
	RuleVersion    = "2"
	MaxScanBytes   = 1 << 20 // 1 MiB per response (§14.3)
)

// FindingSink persists findings (store or in-memory).
type FindingSink interface {
	Record(Finding) Finding
}

// ObserveJob is one post-commit response scan task.
type ObserveJob struct {
	Body             []byte
	Upstream         string
	RouteID          int64
	ReqID            string
	Keys             []string // upstream/relay secrets for Detail redaction (§14.5)
	Spec             protocol.DecoderSpec
	input            ScanInput
	request          []byte
	requestTruncated bool
}

// Observer runs passive scans off the forward path (§14.2–14.3).
// Queue full → drop (never block forwarding).
type Observer struct {
	sink    FindingSink
	queue   chan observeWrite
	stop    chan struct{}
	done    chan struct{}
	dropped atomic.Uint64
	log     *slog.Logger
	wg      sync.WaitGroup
	once    sync.Once
	mu      sync.Mutex
	closed  bool
	slots   chan struct{}
}

type observeWrite struct {
	job     ObserveJob
	barrier chan struct{}
}

// NewObserver starts workers. queueSize defaults to 64.
func NewObserver(sink FindingSink, queueSize int, log *slog.Logger) *Observer {
	if queueSize < 1 {
		queueSize = 64
	}
	if log == nil {
		log = slog.Default()
	}
	o := &Observer{
		sink:  sink,
		queue: make(chan observeWrite, queueSize),
		slots: make(chan struct{}, queueSize+1),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		log:   log,
	}
	o.wg.Add(1)
	go o.loop()
	return o
}

// Enqueue retains the legacy diagnostic entry point with the same bounded
// head/tail, admission and metadata contract as original-wire captures.
func (o *Observer) Enqueue(job ObserveJob) {
	capture := o.Wrap(job)
	capture.TryChunk(job.Body)
	capture.Complete(true)
}

func (o *Observer) reserve() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return false
	}
	select {
	case o.slots <- struct{}{}:
		return true
	default:
		o.dropped.Add(1)
		return false
	}
}

func (o *Observer) release() { <-o.slots }

func (o *Observer) enqueueOwned(job ObserveJob) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		o.release()
		return
	}
	select {
	case o.queue <- observeWrite{job: job}:
	default:
		o.dropped.Add(1)
		o.release()
	}
}

// Flush follows producer drain. The FIFO barrier waits for all earlier scans
// and their synchronous evidence writes without blocking normal Enqueue calls.
func (o *Observer) Flush(ctx context.Context) error {
	if o == nil {
		return nil
	}
	barrier := make(chan struct{})
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case o.queue <- observeWrite{barrier: barrier}:
	}
	select {
	case <-barrier:
		return nil
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Dropped returns how many jobs were discarded due to full queue.
func (o *Observer) Dropped() uint64 {
	if o == nil {
		return 0
	}
	return o.dropped.Load()
}

// Close drains workers.
func (o *Observer) Close() {
	if o == nil {
		return
	}
	o.once.Do(func() {
		o.mu.Lock()
		o.closed = true
		close(o.stop)
		o.mu.Unlock()
		o.wg.Wait()
	})
}

func (o *Observer) loop() {
	defer o.wg.Done()
	defer close(o.done)
	consume := func(value observeWrite) {
		if value.barrier != nil {
			close(value.barrier)
			return
		}
		o.scan(value.job)
		o.release()
	}
	var reported uint64
	reportDropped := func() {
		if dropped := o.dropped.Load(); dropped != reported {
			o.log.Warn("被动安全扫描任务丢弃", "dropped", dropped, "new_dropped", dropped-reported)
			reported = dropped
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer reportDropped()
	for {
		select {
		case <-ticker.C:
			reportDropped()
		case value := <-o.queue:
			consume(value)
		case <-o.stop:
			for {
				select {
				case value := <-o.queue:
					consume(value)
				default:
					return
				}
			}
		}
	}
}

func (o *Observer) scan(job ObserveJob) {
	input := job.input
	if input.Spec.Endpoint != "" {
		input.Context = requestContext(job.request)
		if job.requestTruncated || !input.Context.ToolsKnown {
			input.Context = RequestContext{}
			input.IncompleteReason = appendIncomplete(input.IncompleteReason, "request_context_unknown")
		}
	}
	found := defaultScanner.Scan(input)
	for _, f := range found {
		f.Upstream, f.RouteID, f.ReqID = job.Upstream, job.RouteID, job.ReqID
		f.Source = "passive"
		if o.sink != nil {
			o.sink.Record(f)
		}
	}
}
