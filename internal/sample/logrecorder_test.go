package sample

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// LogRecorder（M6）。
//
// 与 Recorder 的测试同一套关切：**记日志绝不能拖慢或拖垮转发**。
// 差别在于日志的失败还有一层后果 —— 丢掉的行会让重试统计偏低（分母少了），
// 而一个不知道自己不准的统计数字比没有统计更糟。

type fakeLogWriter struct {
	mu    sync.Mutex
	got   []*model.RequestLog
	block chan struct{} // 非 nil 时每次写入都等它
	fail  bool
	calls atomic.Int32
	// written 每落库一条发一个信号，让测试能等到「真的被消费了」
	// 而不是靠 sleep 猜 —— 后台 writer 的进度不可预测。
	written chan struct{}

	pruneCalls atomic.Int32
	pruneArgs  [][2]int
}

func (f *fakeLogWriter) InsertRequestLog(l *model.RequestLog) error {
	f.calls.Add(1)
	if f.block != nil {
		<-f.block
	}
	if f.fail {
		return errors.New("模拟落库失败")
	}
	f.mu.Lock()
	f.got = append(f.got, l)
	f.mu.Unlock()
	if f.written != nil {
		f.written <- struct{}{}
	}
	return nil
}

func (f *fakeLogWriter) PruneRequestLogs(keepCount, keepDays int) (int64, error) {
	f.pruneCalls.Add(1)
	f.mu.Lock()
	f.pruneArgs = append(f.pruneArgs, [2]int{keepCount, keepDays})
	f.mu.Unlock()
	return 0, nil
}

func (f *fakeLogWriter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func (f *fakeLogWriter) lastPrune() ([2]int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pruneArgs) == 0 {
		return [2]int{}, false
	}
	return f.pruneArgs[len(f.pruneArgs)-1], true
}

func testLogSettings() model.Settings {
	s := model.DefaultSettings()
	s.RequestLogQueueSize = 8
	return s
}

func newTestLogRecorder(w LogWriter, s model.Settings) *LogRecorder {
	return NewLogRecorder(w, s, newLiveSettings(s), discardLog())
}

func TestLogRecorder_WritesLogs(t *testing.T) {
	w := &fakeLogWriter{}
	r := newTestLogRecorder(w, testLogSettings())

	for i := 0; i < 5; i++ {
		r.Record(&model.RequestLog{ReqID: "req", Attempt: i + 1})
	}
	r.Close() // Close 会排空队列

	if w.count() != 5 {
		t.Errorf("应落库 5 行，得到 %d", w.count())
	}
	if written, dropped := r.Stats(); written != 5 || dropped != 0 {
		t.Errorf("统计应为 5/0，得到 %d/%d", written, dropped)
	}
}

// 队列满时必须丢弃并计数，**绝不阻塞调用方** ——
// 阻塞就等于让「记日志」拖慢真实转发，主次倒置。
func TestLogRecorder_NeverBlocksWhenFull(t *testing.T) {
	block := make(chan struct{})
	w := &fakeLogWriter{block: block}
	s := testLogSettings()
	s.RequestLogQueueSize = 2
	r := newTestLogRecorder(w, s)

	// 投递远多于队列容量。writer 被 block 卡住，所以队列会满。
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			r.Record(&model.RequestLog{ReqID: "flood", Attempt: i})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Record 阻塞了 —— 记日志绝不能拖慢转发")
	}

	if _, dropped := r.Stats(); dropped == 0 {
		t.Error("队列满时应丢弃并计数 —— 不计数的话「日志怎么少了」无从下手")
	}

	close(block)
	r.Close()
}

// 落库失败只记日志、不重试、不阻塞后续写入。
//
// 重试会让积压更严重，而日志本身是可丢的。
func TestLogRecorder_WriteFailureDoesNotStopWriter(t *testing.T) {
	w := &fakeLogWriter{fail: true}
	r := newTestLogRecorder(w, testLogSettings())

	for i := 0; i < 3; i++ {
		r.Record(&model.RequestLog{ReqID: "req", Attempt: i})
	}
	r.Close()

	if n := w.calls.Load(); n != 3 {
		t.Errorf("三条都该尝试写一次（不重试），得到 %d 次调用", n)
	}
	if written, _ := r.Stats(); written != 0 {
		t.Errorf("失败的不该计入 written，得到 %d", written)
	}
}

// Close 要排空队列：已采集到的日志没理由丢，
// 尤其关闭前那几条往往正是导致关闭的那次故障的现场。
func TestLogRecorder_CloseDrainsQueue(t *testing.T) {
	w := &fakeLogWriter{}
	s := testLogSettings()
	s.RequestLogQueueSize = 64
	r := newTestLogRecorder(w, s)

	for i := 0; i < 20; i++ {
		r.Record(&model.RequestLog{ReqID: "drain", Attempt: i})
	}
	r.Close()

	if w.count() != 20 {
		t.Errorf("Close 应排空队列，落库 %d/20", w.count())
	}
}

// Close 可重复调用（stopOnce），第二次不能 panic。
func TestLogRecorder_CloseIsIdempotent(t *testing.T) {
	r := newTestLogRecorder(&fakeLogWriter{}, testLogSettings())
	r.Close()
	r.Close() // 不能 panic（close of closed channel）
}

// 保留策略每次清理**现读**，不在构造时定格。
//
// 定格的话，用户在管理界面把保留量从 5000 改成 100 后，界面显示新值、
// 库里也是新值，但清理照旧按 5000 执行 —— 一个「改了没反应」
// 且完全不报错的功能。
func TestLogRecorder_RetentionIsReadFresh(t *testing.T) {
	w := &fakeLogWriter{written: make(chan struct{}, 512)}
	s := testLogSettings()
	s.RequestLogQueueSize = 512
	live := newLiveSettings(s)
	r := NewLogRecorder(w, s, live, discardLog())

	// 改成一个显眼的值
	live.set(func(cur *model.Settings) {
		cur.RequestLogKeepCount = 42
		cur.RequestLogKeepDays = 3
	})

	// 触发一次清理：Close 收尾时一定会清一次
	r.Record(&model.RequestLog{ReqID: "x", Attempt: 1})
	r.Close()

	args, ok := w.lastPrune()
	if !ok {
		t.Fatal("应至少清理一次（Close 收尾时）")
	}
	if args[0] != 42 || args[1] != 3 {
		t.Errorf("清理应用**当前**的保留策略 42/3，实际用了 %d/%d —— "+
			"策略被构造时定格了", args[0], args[1])
	}
}

// 配置源读不到时按默认值清，**不能跳过清理**。
//
// 跳过的话，配置源出问题的那段时间日志会无上限堆积 ——
// 而那正是最需要留出磁盘的时候。
func TestLogRecorder_PrunesWithDefaultsWhenSettingsFail(t *testing.T) {
	w := &fakeLogWriter{}
	s := testLogSettings()
	live := newLiveSettings(s)
	live.err = errors.New("配置源坏了")
	r := NewLogRecorder(w, s, live, discardLog())

	r.Record(&model.RequestLog{ReqID: "x", Attempt: 1})
	r.Close()

	args, ok := w.lastPrune()
	if !ok {
		t.Fatal("读不到配置也必须清理，否则日志会无上限堆积")
	}
	d := model.DefaultSettings()
	if args[0] != d.RequestLogKeepCount || args[1] != d.RequestLogKeepDays {
		t.Errorf("应回落到默认保留策略 %d/%d，实际 %d/%d",
			d.RequestLogKeepCount, d.RequestLogKeepDays, args[0], args[1])
	}
}

// 队列大小为 0 或负数时不能建出一个零容量 channel 后死锁。
func TestLogRecorder_ZeroQueueSizeStillWorks(t *testing.T) {
	w := &fakeLogWriter{}
	s := testLogSettings()
	s.RequestLogQueueSize = 0
	r := newTestLogRecorder(w, s)

	r.Record(&model.RequestLog{ReqID: "x", Attempt: 1})
	r.Close()
	// 只要不 panic、不死锁即可 —— 容量 1 的队列可能丢，但不能挂
}

// req_id 必须唯一且不含需要 URL 转义的字符。
//
// 它会出现在查询参数里（?req_id=xxx），带 '=' 的话每个调用方都得记着转义，
// 而漏一处的表现是「详情页偶尔打不开」。
func TestNewReqID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewReqID()
		if id == "" {
			t.Fatal("不该返回空串")
		}
		if seen[id] {
			t.Fatalf("1000 次内就碰撞了：%q", id)
		}
		seen[id] = true

		for _, c := range id {
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				t.Fatalf("req_id 只该含小写字母数字与连字符，得到 %q 里的 %q", id, c)
			}
		}
	}
}
