package probe

// P0-13：真实流量旁路观察。proxy 只依赖 health 接口；本包提供实现。

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
)

const (
	fullObserverLeases   = 32
	globalCopyBudget     = 16 << 20 // 16 MiB
	persistQueueCap      = 1024
	perAttemptQueue      = 32
	perAttemptCopyBudget = 256 << 10 // 256 KiB
)

// TrafficObserverManager 是进程级真实流量旁路限流与持久化入口。
type TrafficObserverManager struct {
	cfg    ProbeSnapshotSource
	seq    *observationseq.Sequencer
	record ExecutionRecorder
	sched  interface {
		ObserveRealSuccess(key ScheduleKey, observedAt time.Time)
	}
	log *slog.Logger

	leases    chan struct{}
	copyBytes atomic.Int64
	queue     chan *model.ProbeObservation
	stop      chan struct{}
	wg        sync.WaitGroup

	capacityDrops  atomic.Uint64
	persistDrops   atomic.Uint64
	candidateDrops atomic.Uint64
	startedAt      time.Time
}

// NewTrafficObserverManager 构造管理器；须在 listener 前启动 Run。
func NewTrafficObserverManager(
	cfg ProbeSnapshotSource,
	seq *observationseq.Sequencer,
	record ExecutionRecorder,
	log *slog.Logger,
) *TrafficObserverManager {
	if log == nil {
		log = slog.Default()
	}
	m := &TrafficObserverManager{
		cfg:       cfg,
		seq:       seq,
		record:    record,
		log:       log,
		leases:    make(chan struct{}, fullObserverLeases),
		queue:     make(chan *model.ProbeObservation, persistQueueCap),
		stop:      make(chan struct{}),
		startedAt: time.Now(),
	}
	for i := 0; i < fullObserverLeases; i++ {
		m.leases <- struct{}{}
	}
	return m
}

// WithScheduler 注入 piggyback 通知面。
func (m *TrafficObserverManager) WithScheduler(s interface {
	ObserveRealSuccess(key ScheduleKey, observedAt time.Time)
}) *TrafficObserverManager {
	m.sched = s
	return m
}

// Run 启动 persistence worker；ctx 取消时有界 drain。
func (m *TrafficObserverManager) Run(ctx context.Context) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case <-ctx.Done():
				m.drainPersist()
				return
			case <-m.stop:
				m.drainPersist()
				return
			case item := <-m.queue:
				m.persistOne(ctx, item)
			}
		}
	}()
	<-ctx.Done()
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

func (m *TrafficObserverManager) drainPersist() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case item := <-m.queue:
			m.persistOne(context.Background(), item)
		default:
			return
		}
	}
}

func (m *TrafficObserverManager) persistOne(ctx context.Context, item *model.ProbeObservation) {
	if m.record == nil || item == nil {
		return
	}
	if _, err := m.record.Record(ctx, item); err != nil {
		m.log.Warn("真实流量观察落库失败", "err", err)
	}
}

// Close 停止接收。
func (m *TrafficObserverManager) Close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

// Stats 返回 since-start 诊断（不含请求数据）。
func (m *TrafficObserverManager) Stats() model.ProbeRuntimeStats {
	return model.ProbeRuntimeStats{
		FullObserversInFlight:    int64(fullObserverLeases - len(m.leases)),
		FullObserverLimit:        fullObserverLeases,
		ObserverBytesInFlight:    m.copyBytes.Load(),
		ObserverByteLimit:        globalCopyBudget,
		ObservationQueueDepth:    int64(len(m.queue)),
		ObservationQueueCapacity: persistQueueCap,
		DroppedByCapacity:        m.capacityDrops.Load(),
		DroppedByPersistence:     m.persistDrops.Load(),
		DroppedCandidates:        m.candidateDrops.Load(),
	}
}

// PrepareAttempt 实现 health.AttemptObserverFactory。
func (m *TrafficObserverManager) PrepareAttempt(ctx context.Context, target health.AttemptTarget, request health.AttemptRequestView) health.AttemptInstrumentation {
	_ = request
	if m == nil {
		return health.NoopInstrumentation()
	}
	snap, err := m.cfg.ProbeSnapshot()
	if err != nil || snap == nil {
		return health.NoopInstrumentation()
	}
	if target.Config.Generation != 0 && snap.Generation != target.Config.Generation {
		return health.NoopInstrumentation()
	}

	var order int64
	if m.seq != nil {
		o, oerr := m.seq.Next(ctx, model.TriggerRealTraffic)
		if oerr != nil {
			return health.NoopInstrumentation()
		}
		order = o
	}

	trace := &outbound.AttemptTrace{}
	full := false
	select {
	case <-m.leases:
		full = true
	default:
		m.capacityDrops.Add(1)
	}

	obs := &trafficObserver{
		m:      m,
		target: target,
		order:  order,
		trace:  trace,
		full:   full,
		queue:  make(chan trafficEvent, perAttemptQueue),
		stop:   make(chan struct{}),
	}
	if full {
		obs.wg.Add(1)
		go obs.worker()
	}
	return health.AttemptInstrumentation{
		Observer: obs,
		Retry:    NewRetryDecider(target.Protocol),
		Trace:    trace,
	}
}

type trafficEvent struct {
	kind   string
	status int
	header http.Header
	chunk  []byte
	at     time.Time
}

type trafficObserver struct {
	m      *TrafficObserverManager
	target health.AttemptTarget
	order  int64
	trace  *outbound.AttemptTrace
	full   bool

	mu         sync.Mutex
	incomplete string
	status     int
	header     http.Header
	finished   bool
	copyUsed   int64

	queue chan trafficEvent
	stop  chan struct{}
	wg    sync.WaitGroup
}

func (o *trafficObserver) TryHeaders(status int, header http.Header, at time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished || o.incomplete != "" {
		return false
	}
	o.status = status
	if header != nil {
		o.header = header.Clone()
	}
	if o.trace != nil {
		o.trace.MarkResponseHeader(at)
	}
	if !o.full {
		return true
	}
	select {
	case o.queue <- trafficEvent{kind: "headers", status: status, header: o.header, at: at}:
	default:
		o.incomplete = "observer_incomplete"
	}
	return true
}

func (o *trafficObserver) TryChunk(chunk []byte, at time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished || o.incomplete != "" || !o.full || len(chunk) == 0 {
		return false
	}
	n := len(chunk)
	if o.copyUsed+int64(n) > perAttemptCopyBudget {
		o.incomplete = "observer_incomplete"
		return false
	}
	for {
		cur := o.m.copyBytes.Load()
		if cur+int64(n) > globalCopyBudget {
			o.incomplete = "observer_incomplete"
			o.m.capacityDrops.Add(1)
			return false
		}
		if o.m.copyBytes.CompareAndSwap(cur, cur+int64(n)) {
			break
		}
	}
	cp := make([]byte, n)
	copy(cp, chunk)
	o.copyUsed += int64(n)
	select {
	case o.queue <- trafficEvent{kind: "chunk", chunk: cp, at: at}:
		return true
	default:
		o.m.copyBytes.Add(-int64(n))
		o.copyUsed -= int64(n)
		o.incomplete = "observer_incomplete"
		return false
	}
}

func (o *trafficObserver) Finish(v health.AttemptFinish) {
	o.mu.Lock()
	if o.finished {
		o.mu.Unlock()
		return
	}
	o.finished = true
	status := o.status
	incomplete := o.incomplete
	full := o.full
	o.mu.Unlock()

	if o.trace != nil {
		o.trace.MarkDone(time.Now())
	}
	close(o.stop)
	if full {
		o.wg.Wait()
		select {
		case o.m.leases <- struct{}{}:
		default:
		}
	}

	snap := o.trace.Snapshot()
	exec := model.ProbeExecution{
		ObservationOrder:      o.order,
		Trigger:               model.TriggerRealTraffic,
		UpstreamID:            o.target.UpstreamID,
		RouteID:               o.target.RouteID,
		Endpoint:              o.target.Endpoint,
		EndpointID:            o.target.Config.EndpointID,
		StatusCode:            status,
		ResolvedURLHash:       o.target.Config.ResolvedURLHash,
		SentAtMS:              msOrZero(snap.SentAt),
		GotConnAtMS:           msOrZero(snap.GotConnAt),
		ResponseHeaderAtMS:    msOrZero(snap.ResponseHeaderAt),
		DoneAtMS:              msOrZero(snap.DoneAt),
		TLSHandshakeStartAtMS: msOrZero(snap.TLSStartAt),
		TLSHandshakeDoneAtMS:  msOrZero(snap.TLSDoneAt),
	}
	if incomplete != "" {
		exec.ObserverIncomplete = true
		exec.ErrorClass = model.ErrorIgnored
		exec.RedactedDetail = incomplete
	}
	if v.ClientCanceled || v.ServiceCanceled {
		exec.ErrorClass = model.ErrorIgnored
	}
	// §6.8 / §8.12：旁路观察器当前不解析 body（TryChunk 未接线），不得仅凭
	// 2xx 置 Success 或调用 ObserveRealSuccess —— 否则 `{"type":"error"}`
	// 会把 Route 拉活并 piggyback 掉合成 L2。真实成功由 ReportResult →
	// classifyReal → VerdictOK 写入 lastRealOKAt（§8.10）。
	if status > 0 && exec.ErrorClass == "" {
		exec.Reachable = true
	}

	obs := &model.ProbeObservation{Execution: exec}
	select {
	case o.m.queue <- obs:
	default:
		o.m.persistDrops.Add(1)
	}
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func (o *trafficObserver) worker() {
	defer o.wg.Done()
	for {
		select {
		case <-o.stop:
			for {
				select {
				case ev := <-o.queue:
					if len(ev.chunk) > 0 {
						o.m.copyBytes.Add(-int64(len(ev.chunk)))
					}
				default:
					return
				}
			}
		case ev := <-o.queue:
			if len(ev.chunk) > 0 {
				o.m.copyBytes.Add(-int64(len(ev.chunk)))
			}
		}
	}
}

var (
	_ health.AttemptObserverFactory = (*TrafficObserverManager)(nil)
	_ health.AttemptObserver        = (*trafficObserver)(nil)
	_ ProbeSnapshotSource           = (*livecfg.Source)(nil)
)
