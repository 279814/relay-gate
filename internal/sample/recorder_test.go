package sample

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeWriter 可控地阻塞或失败，用于验证「记录绝不影响转发」。
type fakeWriter struct {
	mu      sync.Mutex
	got     []*model.Sample
	block   chan struct{} // 非 nil 时每次写入都等它
	failNth int32         // >0 时第 N 次写入失败
	calls   atomic.Int32
	// written 每落库一条发一个信号，让测试能等到「真的被消费了」
	// 而不是靠 sleep 猜 —— 后台 writer 的进度不可预测。
	written chan struct{}

	pruneCalls atomic.Int32
	pruneArgs  []([2]int)
}

func (f *fakeWriter) InsertSample(s *model.Sample) error {
	n := f.calls.Add(1)
	if f.block != nil {
		<-f.block
	}
	if f.failNth > 0 && n == f.failNth {
		return errors.New("模拟落库失败")
	}
	f.mu.Lock()
	f.got = append(f.got, s)
	f.mu.Unlock()
	if f.written != nil {
		f.written <- struct{}{}
	}
	return nil
}

func (f *fakeWriter) PruneSamples(keepCount, keepDays int) (int64, error) {
	f.pruneCalls.Add(1)
	f.mu.Lock()
	f.pruneArgs = append(f.pruneArgs, [2]int{keepCount, keepDays})
	f.mu.Unlock()
	return 0, nil
}

func (f *fakeWriter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func testSettings() model.Settings {
	s := model.DefaultSettings()
	s.SampleQueueSize = 8
	return s
}

func TestRecorder_WritesSamples(t *testing.T) {
	w := &fakeWriter{}
	r := NewRecorder(w, testSettings(), discardLog())

	for i := 0; i < 5; i++ {
		r.Record(&model.Sample{RouteID: int64(i)})
	}
	r.Close() // Close 会排空队列

	if got := w.count(); got != 5 {
		t.Errorf("应写入 5 条，得到 %d", got)
	}
	if written, dropped := r.Stats(); written != 5 || dropped != 0 {
		t.Errorf("Stats 应为 written=5 dropped=0，得到 %d/%d", written, dropped)
	}
}

// §9.4：记录 channel 打满 → 丢样本 + 计数递增，**转发不受影响、不阻塞、不报错**。
//
// 这是整个样本功能最重要的一条：宁可丢样本，也绝不让「记日志」拖慢转发。
func TestRecorder_DropsWhenFullNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	w := &fakeWriter{block: block}
	s := testSettings()
	s.SampleQueueSize = 4
	r := NewRecorder(w, s, discardLog())

	// 后台 writer 会卡在第一条上，队列很快填满
	const total = 100
	start := time.Now()
	for i := 0; i < total; i++ {
		r.Record(&model.Sample{RouteID: int64(i)})
	}
	elapsed := time.Since(start)

	// 关键断言：100 次投递必须几乎瞬间返回，绝不等待
	if elapsed > 200*time.Millisecond {
		t.Errorf("投递阻塞了 %v —— Record 必须非阻塞", elapsed)
	}
	_, dropped := r.Stats()
	if dropped == 0 {
		t.Error("队列满时应丢弃并计数")
	}
	if dropped < total-int64(s.SampleQueueSize)-2 {
		t.Errorf("丢弃计数不合理：投递 %d 条、队列 %d，只记了 %d 条丢弃",
			total, s.SampleQueueSize, dropped)
	}

	close(block)
	r.Close()
}

// 落库失败只记日志，不重试、不阻塞、不影响后续样本。
func TestRecorder_ContinuesAfterWriteError(t *testing.T) {
	w := &fakeWriter{failNth: 2}
	r := NewRecorder(w, testSettings(), discardLog())

	for i := 0; i < 4; i++ {
		r.Record(&model.Sample{RouteID: int64(i)})
	}
	r.Close()

	if got := w.count(); got != 3 {
		t.Errorf("失败 1 条后其余 3 条仍应写入，得到 %d", got)
	}
	if written, _ := r.Stats(); written != 3 {
		t.Errorf("written 不该把失败的算进去，得到 %d", written)
	}
}

// Close 必须排空队列：关闭前那几条样本往往正是导致关闭的那次故障的现场。
func TestRecorder_CloseDrainsQueue(t *testing.T) {
	w := &fakeWriter{}
	s := testSettings()
	s.SampleQueueSize = 64
	r := NewRecorder(w, s, discardLog())

	for i := 0; i < 30; i++ {
		r.Record(&model.Sample{RouteID: int64(i)})
	}
	r.Close()

	if got := w.count(); got != 30 {
		t.Errorf("Close 应排空队列，应写入 30 条，得到 %d", got)
	}
}

// Close 幂等：优雅关闭路径上可能被 defer 与显式调用重复触发。
func TestRecorder_CloseIsIdempotent(t *testing.T) {
	r := NewRecorder(&fakeWriter{}, testSettings(), discardLog())
	r.Close()
	r.Close() // 不该 panic（close of closed channel）
	r.Close()
}

// Close 之后再投递不能 panic —— 转发协程可能还在收尾。
func TestRecorder_RecordAfterCloseDoesNotPanic(t *testing.T) {
	r := NewRecorder(&fakeWriter{}, testSettings(), discardLog())
	r.Close()

	// 队列还有空间就进队列（无人消费），满了就丢，两种都不该 panic
	for i := 0; i < 100; i++ {
		r.Record(&model.Sample{RouteID: int64(i)})
	}
}

// 清理按写入量触发，不是每条都清 —— SQLite 单连接，每条都清会积压。
func TestRecorder_PrunesPeriodically(t *testing.T) {
	const n = pruneEvery + 5
	w := &fakeWriter{written: make(chan struct{}, n)}
	s := testSettings()
	s.SampleQueueSize = 256
	s.SampleKeepCount = 500
	s.SampleKeepDays = 7
	r := NewRecorder(w, s, discardLog())

	for i := 0; i < n; i++ {
		r.Record(&model.Sample{RouteID: 1})
	}
	// 等这 n 条真的被后台 writer 消费掉再断言。
	// 直接 Close 是不行的：Close 关掉 stop 后，loop 的 select 两个 case
	// 同时就绪，Go 随机挑 —— 挑到 stop 就走排空路径，周期清理还没轮到，
	// 测试就变成随机通过。
	for i := 0; i < n; i++ {
		select {
		case <-w.written:
		case <-time.After(5 * time.Second):
			t.Fatalf("等待第 %d 条落库超时", i+1)
		}
	}

	if got := w.pruneCalls.Load(); got < 1 {
		t.Errorf("写入 %d 条（≥ pruneEvery=%d）应触发周期清理，实际 %d 次",
			n, pruneEvery, got)
	}
	// 清理参数必须来自 Settings，写死的话改配置不生效
	w.mu.Lock()
	args := append([][2]int(nil), w.pruneArgs...)
	w.mu.Unlock()
	if len(args) == 0 || args[0] != [2]int{500, 7} {
		t.Errorf("清理参数应取自 Settings，得到 %v", args)
	}

	r.Close()
}

// 不能每条都清：清理是 DELETE + 索引维护，SQLite 单连接下会让写入队列积压。
func TestRecorder_DoesNotPrunePerSample(t *testing.T) {
	const n = 5 // 远小于 pruneEvery
	w := &fakeWriter{written: make(chan struct{}, n)}
	s := testSettings()
	s.SampleQueueSize = 64
	r := NewRecorder(w, s, discardLog())

	for i := 0; i < n; i++ {
		r.Record(&model.Sample{RouteID: 1})
	}
	for i := 0; i < n; i++ {
		<-w.written
	}

	if got := w.pruneCalls.Load(); got != 0 {
		t.Errorf("少于 pruneEvery 条时不该清理，实际调用 %d 次", got)
	}

	// 但关闭时要收尾清理一次
	r.Close()
	if got := w.pruneCalls.Load(); got != 1 {
		t.Errorf("Close 应收尾清理一次，实际 %d 次", got)
	}
}

// 并发投递不能丢计数或撕裂。
func TestRecorder_ConcurrentRecord(t *testing.T) {
	w := &fakeWriter{}
	s := testSettings()
	s.SampleQueueSize = 512
	r := NewRecorder(w, s, discardLog())

	const goroutines, each = 20, 25
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < each; j++ {
				r.Record(&model.Sample{RouteID: int64(id)})
			}
		}(i)
	}
	wg.Wait()
	r.Close()

	written, dropped := r.Stats()
	if written+dropped != goroutines*each {
		t.Errorf("写入 + 丢弃应等于投递总数 %d，得到 %d + %d",
			goroutines*each, written, dropped)
	}
}

// 队列大小配成 0 或负数时要兜底为 1，不能 make(chan, -1) panic。
func TestRecorder_InvalidQueueSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		s := testSettings()
		s.SampleQueueSize = size
		r := NewRecorder(&fakeWriter{}, s, discardLog())
		r.Record(&model.Sample{})
		r.Close()
	}
}
