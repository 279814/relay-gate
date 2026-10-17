package security

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

const (
	ScannerVersion = "1"
	RuleVersion    = "1"
	MaxScanBytes   = 1 << 20 // 1 MiB per response (§14.3)
)

// FindingSink persists findings (store or in-memory).
type FindingSink interface {
	Record(Finding) Finding
}

// ObserveJob is one post-commit response scan task.
type ObserveJob struct {
	Body     []byte
	Upstream string
	RouteID  int64
	ReqID    string
	Keys     []string // upstream/relay secrets for Detail redaction (§14.5)
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
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		log:   log,
	}
	o.wg.Add(1)
	go o.loop()
	return o
}

// Enqueue non-blocking. Copies at most MaxScanBytes of body.
func (o *Observer) Enqueue(job ObserveJob) {
	if o == nil {
		return
	}
	select {
	case <-o.stop:
		return
	default:
	}
	if len(job.Body) > MaxScanBytes {
		job.Body = append([]byte(nil), job.Body[:MaxScanBytes]...)
	} else if job.Body != nil {
		job.Body = append([]byte(nil), job.Body...)
	}
	select {
	case o.queue <- observeWrite{job: job}:
	default:
		o.dropped.Add(1)
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
		close(o.stop)
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
	}
	for {
		select {
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
	text := string(job.Body)
	found := ScanText(text, "traffic", job.Keys...)
	if len(found) == 0 && len(job.Body) >= MaxScanBytes {
		found = []Finding{{
			Severity:         SeverityInfo,
			Category:         "incomplete",
			Summary:          "扫描达到字节上限",
			IncompleteReason: "max_scan_bytes",
			Source:           "passive",
		}}
	}
	for _, f := range found {
		f.Upstream = job.Upstream
		f.RouteID = job.RouteID
		f.ReqID = job.ReqID
		f.ScannerVersion = ScannerVersion
		f.RuleVersion = RuleVersion
		f.BytesScanned = int64(len(job.Body))
		f.Source = "passive"
		if o.sink != nil {
			o.sink.Record(f)
		}
	}
}
