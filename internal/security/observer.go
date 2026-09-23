package security

import (
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
	queue   chan ObserveJob
	dropped atomic.Uint64
	log     *slog.Logger
	wg      sync.WaitGroup
	once    sync.Once
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
		queue: make(chan ObserveJob, queueSize),
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
	if len(job.Body) > MaxScanBytes {
		job.Body = append([]byte(nil), job.Body[:MaxScanBytes]...)
	} else if job.Body != nil {
		job.Body = append([]byte(nil), job.Body...)
	}
	select {
	case o.queue <- job:
	default:
		o.dropped.Add(1)
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
		close(o.queue)
		o.wg.Wait()
	})
}

func (o *Observer) loop() {
	defer o.wg.Done()
	for job := range o.queue {
		o.scan(job)
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
