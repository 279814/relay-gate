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
	cfg            ProbeSnapshotSource
	seq            *observationseq.Sequencer
	record         ExecutionRecorder
	tracker        Tracker
	learner        *Learner
	piggybackStore CostDailyStore
	sched          interface {
		ObserveRealSuccess(key ScheduleKey, observedAt time.Time)
	}
	log *slog.Logger

	leases               chan struct{}
	copyBytes            atomic.Int64
	queue                chan trafficWrite
	stop                 chan struct{}
	observerMu           sync.Mutex
	active               map[*trafficObserver]struct{}
	workersIdle          chan struct{}
	stopOnce             sync.Once
	stopping, runStarted bool
	runCancel            context.CancelFunc
	runDone              chan struct{}

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
		cfg:         cfg,
		seq:         seq,
		record:      record,
		log:         log,
		leases:      make(chan struct{}, fullObserverLeases),
		queue:       make(chan trafficWrite, persistQueueCap),
		stop:        make(chan struct{}),
		startedAt:   time.Now(),
		active:      make(map[*trafficObserver]struct{}),
		workersIdle: make(chan struct{}),
		runDone:     make(chan struct{}),
	}
	close(m.workersIdle)
	for i := 0; i < fullObserverLeases; i++ {
		m.leases <- struct{}{}
	}
	return m
}

type trafficWrite struct {
	healthIdentity *model.RouteHealthIdentity
	observation    *model.ProbeObservation
	target         health.AttemptTarget
	finish         health.AttemptFinish
	barrier        chan error
	shape          model.ClientRequestShape
	piggyback      *model.ProbeCostDaily
	eventID        string
}

func (m *TrafficObserverManager) WithHealthTracker(tracker Tracker) *TrafficObserverManager {
	m.tracker = tracker
	return m
}

func (m *TrafficObserverManager) WithLearner(learner *Learner) *TrafficObserverManager {
	m.learner = learner
	return m
}

func (m *TrafficObserverManager) WithPiggybackStore(store CostDailyStore) *TrafficObserverManager {
	m.piggybackStore = store
	return m
}

func (m *TrafficObserverManager) RecordPiggybackSkip(eventID string, value model.ProbeCostDaily) bool {
	if m.piggybackStore == nil {
		return false
	}
	select {
	case <-m.stop:
		return false
	default:
	}
	select {
	case m.queue <- trafficWrite{eventID: eventID, piggyback: &value}:
		return true
	default:
		m.persistDrops.Add(1)
		return false
	}
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
	m.observerMu.Lock()
	if m.runStarted {
		m.observerMu.Unlock()
		return
	}
	m.runStarted = true
	workerCtx, cancel := context.WithCancel(ctx)
	m.runCancel = cancel
	if m.stopping {
		cancel()
	}
	m.observerMu.Unlock()
	defer close(m.runDone)
	defer cancel()
	for {
		select {
		case <-workerCtx.Done():
			m.stopObservers()
			m.drainPersist(workerCtx)
			return
		case item := <-m.queue:
			m.persistOne(workerCtx, item)
		}
	}
}

func (m *TrafficObserverManager) drainPersist(ctx context.Context) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case item := <-m.queue:
			// Pass Run's ctx (may already be cancelled) so an in-flight
			// insert can abort and bg.Wait is not stuck on Background().
			m.persistOne(ctx, item)
		default:
			return
		}
	}
}

func (m *TrafficObserverManager) persistOne(ctx context.Context, item trafficWrite) {
	defer func() {
		if recover() != nil {
			m.persistDrops.Add(1)
			m.log.Warn("真实流量观察后台回调失败")
		}
	}()
	if item.barrier != nil {
		item.barrier <- nil
		return
	}
	if item.piggyback != nil {
		if err := m.piggybackStore.RecordProbePiggybackSaving(ctx, item.eventID, *item.piggyback); err != nil {
			m.persistDrops.Add(1)
			m.log.Warn("真实成功节省成本记录失败")
		}
		return
	}
	if m.record == nil || item.observation == nil {
		return
	}
	result, err := m.record.Record(ctx, item.observation)
	if err != nil {
		m.persistDrops.Add(1)
		m.log.Warn("真实流量观察落库失败", "err", err)
		return
	}
	m.applyHealth(item, result)
	if m.learner != nil && item.observation.Execution.Success && item.observation.Execution.RealRequestShapeLearnable &&
		result.Capability == model.ApplyCurrent && result.CommittedCapability != nil && result.CommittedCapability.State == model.CapabilitySupported {
		if err := m.learner.ObserveSuccessful(ctx, item.observation.Execution.UpstreamID, item.observation.Execution.Endpoint, item.shape); err != nil {
			m.candidateDrops.Add(1)
			m.log.Warn("真实流量候选学习未保存")
		}
	}
}

// Close 停止接收。
func (m *TrafficObserverManager) Close() {
	m.stopObservers()
	m.observerMu.Lock()
	running := m.runStarted
	m.observerMu.Unlock()
	if running {
		<-m.runDone
	}
}

func (m *TrafficObserverManager) stopObservers() {
	m.observerMu.Lock()
	m.stopping = true
	m.stopOnce.Do(func() { close(m.stop) })
	cancel := m.runCancel
	observers := make([]*trafficObserver, 0, len(m.active))
	for observer := range m.active {
		observers = append(observers, observer)
	}
	idle := m.workersIdle
	m.observerMu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, observer := range observers {
		observer.Finish(health.AttemptFinish{ServiceCanceled: true})
	}
	select {
	case <-idle:
	case <-time.After(2 * time.Second):
	}
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
	select {
	case <-m.stop:
		return health.NoopInstrumentation()
	default:
	}
	var snap *livecfg.ProbeSnapshot
	var err error
	if captured := livecfg.CapturedProbeSnapshot(ctx); captured != nil {
		snap = captured
	} else if cached, ok := m.cfg.(interface {
		CachedProbeSnapshot() (*livecfg.ProbeSnapshot, error)
	}); ok {
		snap, err = cached.CachedProbeSnapshot()
	} else {
		snap, err = m.cfg.ProbeSnapshot()
	}
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
	capability := prepareCapabilityTraffic(ctx, snap, target, order)
	if capability == nil {
		return health.NoopInstrumentation()
	}
	full := false
	select {
	case <-m.leases:
		full = true
	default:
		m.capacityDrops.Add(1)
	}

	obs := &trafficObserver{
		m:          m,
		target:     target,
		order:      order,
		trace:      trace,
		full:       full,
		queue:      make(chan trafficEvent, perAttemptQueue),
		stop:       make(chan struct{}),
		capability: capability,
	}
	obs.progress.changes = make(chan struct{}, 1)
	capability.progress = &obs.progress
	if !full {
		obs.progress.fail(model.ObserverCapacity)
	}
	if len(request.Body) > 0 || len(request.Header) > 0 {
		obs.TryRequest(request)
	}
	if full {
		m.observerMu.Lock()
		if m.stopping {
			m.observerMu.Unlock()
			m.leases <- struct{}{}
			return health.NoopInstrumentation()
		}
		if len(m.active) == 0 {
			m.workersIdle = make(chan struct{})
		}
		m.active[obs] = struct{}{}
		m.observerMu.Unlock()
		go obs.worker()
	}
	return health.AttemptInstrumentation{
		ObservationPrepared: true,
		Observer:            obs,
		Retry:               NewRetryDecider(target.Protocol),
		Trace:               trace,
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
	m          *TrafficObserverManager
	target     health.AttemptTarget
	order      int64
	trace      *outbound.AttemptTrace
	full       bool
	capability *capabilityTraffic
	progress   trafficProgress

	mu          sync.Mutex
	incomplete  model.ObserverIncompleteReason
	status      int
	header      http.Header
	finished    bool
	copyUsed    int64
	wireBytes   int64
	firstByteAt time.Time
	finishView  health.AttemptFinish

	queue chan trafficEvent
	stop  chan struct{}
}

func (o *trafficObserver) TryHeaders(status int, header http.Header, at time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	defer func() { o.progress.fail(o.incomplete) }()
	if o.finished || o.incomplete != "" {
		return false
	}
	o.status = status
	if o.trace != nil {
		o.trace.MarkResponseHeader(at)
	}
	bytes, valuesCount := 0, 0
	for name, values := range header {
		bytes += len(name)
		if bytes > 16<<10 {
			o.incomplete = model.ObserverInputLimit
			o.m.capacityDrops.Add(1)
			return false
		}
		for _, value := range values {
			bytes += len(value)
			valuesCount++
			if bytes > 16<<10 || valuesCount > 128 {
				o.incomplete = model.ObserverInputLimit
				o.m.capacityDrops.Add(1)
				return false
			}
		}
	}
	if header != nil {
		o.header = header.Clone()
	}
	if !o.full {
		return true
	}
	select {
	case o.queue <- trafficEvent{kind: "headers", status: status, header: o.header, at: at}:
	default:
		o.incomplete = model.ObserverQueueFull
	}
	return true
}

func (o *trafficObserver) TryChunk(chunk []byte, at time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	defer func() { o.progress.fail(o.incomplete) }()
	if o.finished || len(chunk) == 0 {
		return false
	}
	n := len(chunk)
	o.wireBytes += int64(n)
	if o.firstByteAt.IsZero() {
		o.firstByteAt = at
	}
	if o.incomplete != "" || !o.full {
		return false
	}
	if o.copyUsed+int64(n) > perAttemptCopyBudget {
		o.incomplete = model.ObserverInputLimit
		return false
	}
	for {
		cur := o.m.copyBytes.Load()
		if cur+int64(n) > globalCopyBudget {
			o.incomplete = model.ObserverCapacity
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
		o.incomplete = model.ObserverQueueFull
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
	o.finishView = v
	full := o.full
	o.mu.Unlock()

	if o.trace != nil {
		o.trace.MarkDone(time.Now())
	}
	close(o.stop)
	if !full {
		o.queueCapabilityObservation()
	}
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func (o *trafficObserver) worker() {
	defer func() {
		o.m.observerMu.Lock()
		delete(o.m.active, o)
		if len(o.m.active) == 0 {
			close(o.m.workersIdle)
		}
		o.m.observerMu.Unlock()
	}()
	defer func() {
		if recover() != nil {
			o.mu.Lock()
			o.incomplete = model.ObserverPanic
			o.mu.Unlock()
			o.capability.decodeErr = errTrafficObserverPanic
			o.progress.fail(model.ObserverPanic)
		}
		<-o.stop
		for {
			select {
			case event := <-o.queue:
				if len(event.chunk) > 0 {
					o.m.copyBytes.Add(-int64(len(event.chunk)))
				}
			default:
				goto drained
			}
		}
	drained:
		o.m.leases <- struct{}{}
		o.queueCapabilityObservation()
	}()
	for {
		select {
		case <-o.stop:
			for {
				select {
				case ev := <-o.queue:
					o.consume(ev)
				default:
					return
				}
			}
		case ev := <-o.queue:
			o.consume(ev)
		}
	}
}

func (o *trafficObserver) consume(event trafficEvent) {
	defer func() {
		if len(event.chunk) > 0 {
			o.m.copyBytes.Add(-int64(len(event.chunk)))
		}
		if o.capability.decodeErr != nil {
			o.progress.fail(model.ObserverDecodeFailure)
		}
	}()
	o.capability.consume(event)
	if event.kind == "headers" && o.capability.decodeErr == nil && o.capability.encoding != "" && o.capability.encoding != "identity" {
		o.decodeCompressed()
	}
}

var (
	_ health.AttemptObserverFactory  = (*TrafficObserverManager)(nil)
	_ health.AttemptObserver         = (*trafficObserver)(nil)
	_ health.AttemptResponseProgress = (*trafficObserver)(nil)
	_ ProbeSnapshotSource            = (*livecfg.Source)(nil)
)
