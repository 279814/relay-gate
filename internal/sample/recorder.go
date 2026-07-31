package sample

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// Writer 把样本落库。由 store 实现，这里只依赖接口便于测试。
type Writer interface {
	InsertSample(s *model.Sample) error
	// PruneSamples 按条数与天数滚动清理，返回删除条数。pinned 豁免。
	PruneSamples(keepCount, keepDays int) (int64, error)
}

// pruneEvery 是每写入多少条样本触发一次清理。
//
// 不每条都清：清理是 DELETE + 索引维护，而 SQLite 只有一条连接，
// 每条样本都清会让写入队列积压。也不用定时器：没有流量时不需要清理，
// 按写入量触发天然与增长速度匹配。
const pruneEvery = 50

// Recorder 是样本记录的旁路管道（§3.6.3a）。
//
// 结构就是「有界 channel + 后台单 writer」：
//   - 代理协程只做一次**非阻塞**投递，channel 满了立刻丢弃并计数
//   - 落库全在后台单 goroutine 里，与转发路径完全解耦
//
// 宁可丢样本，也绝不让「记日志」拖慢或拖垮转发。这是主次关系，不能倒置：
// 一个丢掉的样本只是少一条诊断数据，一个被拖慢的请求是用户可感知的故障。
type Recorder struct {
	ch  chan *model.Sample
	w   Writer
	log *slog.Logger

	// dropped 记录因队列满而丢弃的样本数，暴露在 UI（§3.6.3a）。
	// 不暴露的话，「样本怎么少了几条」会变成无从下手的疑问。
	dropped atomic.Int64
	written atomic.Int64

	keepCount, keepDays int

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// NewRecorder 创建并启动后台 writer。调用方必须在关闭时调用 Close。
func NewRecorder(w Writer, s model.Settings, log *slog.Logger) *Recorder {
	size := s.SampleQueueSize
	if size < 1 {
		size = 1
	}
	r := &Recorder{
		ch:        make(chan *model.Sample, size),
		w:         w,
		log:       log,
		keepCount: s.SampleKeepCount,
		keepDays:  s.SampleKeepDays,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go r.loop()
	return r
}

// Record 非阻塞投递。队列满时丢弃并计数，**绝不阻塞调用方**。
func (r *Recorder) Record(s *model.Sample) {
	select {
	case r.ch <- s:
	default:
		n := r.dropped.Add(1)
		// 只在头几次与每 100 次记一条日志：满队列往往持续一段时间，
		// 每条都记会把日志刷爆，反而盖掉真正需要看的错误。
		if n <= 3 || n%100 == 0 {
			r.log.Warn("样本队列已满，丢弃样本",
				"dropped_total", n, "queue_size", cap(r.ch))
		}
	}
}

// Stats 返回已写入与已丢弃的计数，供管理界面展示。
func (r *Recorder) Stats() (written, dropped int64) {
	return r.written.Load(), r.dropped.Load()
}

func (r *Recorder) loop() {
	defer close(r.done)
	var since int
	for {
		select {
		case s := <-r.ch:
			r.write(s)
			if since++; since >= pruneEvery {
				since = 0
				r.prune()
			}
		case <-r.stop:
			// 排空队列：已经采集到的样本没理由丢，尤其关闭前那几条
			// 往往正是导致关闭的那次故障的现场。
			for {
				select {
				case s := <-r.ch:
					r.write(s)
				default:
					r.prune()
					return
				}
			}
		}
	}
}

func (r *Recorder) write(s *model.Sample) {
	if err := r.w.InsertSample(s); err != nil {
		// 只记日志，不重试：重试会让积压更严重，而样本本身是可丢的。
		r.log.Error("样本落库失败", "err", err, "route", s.RouteID)
		return
	}
	r.written.Add(1)
}

func (r *Recorder) prune() {
	n, err := r.w.PruneSamples(r.keepCount, r.keepDays)
	if err != nil {
		r.log.Error("清理样本失败", "err", err)
		return
	}
	if n > 0 {
		r.log.Debug("已清理过期样本", "deleted", n)
	}
}

// Close 停止后台 writer 并等它排空队列。
//
// 有等待上限：优雅关闭已经有自己的总时限，样本落库不该成为延长它的理由。
func (r *Recorder) Close() {
	r.stopOnce.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		r.log.Warn("样本 writer 未在 5 秒内收尾，放弃等待",
			"pending", len(r.ch))
	}
}
