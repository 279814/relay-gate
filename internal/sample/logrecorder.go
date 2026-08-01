package sample

import (
	"crypto/rand"
	"encoding/base32"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// LogWriter 把请求日志落库。由 store 实现。
type LogWriter interface {
	InsertRequestLog(l *model.RequestLog) error
	// PruneRequestLogs 按条数与天数滚动清理，返回删除行数。
	PruneRequestLogs(keepCount, keepDays int) (int64, error)
}

// logPruneEvery 是每写入多少行触发一次清理。
//
// 比样本的 50 大：日志一次客户端请求可能写多行（每次尝试一行），
// 用同样的阈值会让清理跑得更频繁，而每行的成本比样本低得多。
const logPruneEvery = 200

// LogRecorder 是请求日志的旁路管道（M6）。
//
// 形状与 Recorder 相同（有界 channel + 后台单 writer + 满则丢），理由也相同：
// 记日志绝不能拖慢转发（§3.6.3a 的主次关系对日志同样成立）。
//
// **但它是独立的一份**，不是 Recorder 的一个模式。原因：
//
//  1. 样本可以关（sample_enabled），日志不该跟着关 —— 日志是判断
//     「重试策略有没有用」的唯一依据，而那个判断恰恰在样本被关掉、
//     只留统计的场景下最需要。
//  2. 两者的保留策略必然不同：样本一条几 MB（现在不封顶），日志一行几百字节。
//     共用一个 keep_count 会让「多留日志」的代价是磁盘翻 GB。
//  3. 队列共用会让日志被样本挤掉：一次三连重试写 3 行日志 + 1 条样本，
//     而样本大得多、落库慢得多，队列一满先丢的是排在后面的日志。
//
// 复用的是**形状**而不是实例 —— 两个类型的字段几乎相同，但那是因为
// 「有界 channel + 单 writer」本来就是这个问题的正确答案，不是重复。
type LogRecorder struct {
	ch  chan *model.RequestLog
	w   LogWriter
	log *slog.Logger

	dropped atomic.Int64
	written atomic.Int64

	// retention 每次清理时现读，理由同 Recorder.retention：
	// 定格的话，用户在界面改了保留量之后清理照旧按旧值执行 ——
	// 一个「改了没反应」且完全不报错的功能。
	retention RetentionSource

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// NewLogRecorder 创建并启动后台 writer。调用方必须在关闭时调用 Close。
//
// s 只用于取队列大小（channel 容量，改它必须重启）；
// 保留策略走 retention 现读。
func NewLogRecorder(w LogWriter, s model.Settings, retention RetentionSource,
	log *slog.Logger) *LogRecorder {

	size := s.RequestLogQueueSize
	if size < 1 {
		size = 1
	}
	r := &LogRecorder{
		ch:        make(chan *model.RequestLog, size),
		w:         w,
		log:       log,
		retention: retention,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go r.loop()
	return r
}

// Record 非阻塞投递。队列满时丢弃并计数，**绝不阻塞调用方**。
func (r *LogRecorder) Record(l *model.RequestLog) {
	select {
	case r.ch <- l:
	default:
		n := r.dropped.Add(1)
		// 只在头几次与每 100 次记一条：满队列往往持续一段时间，
		// 每条都记会把日志刷爆，反而盖掉真正需要看的错误。
		if n <= 3 || n%100 == 0 {
			r.log.Warn("请求日志队列已满，丢弃日志",
				"dropped_total", n, "queue_size", cap(r.ch))
		}
	}
}

// Stats 返回已写入与已丢弃的行数，供管理界面展示。
//
// dropped 必须暴露：丢掉的日志会让重试统计**偏低**（分母少了），
// 而一个不知道自己不准的统计数字比没有统计更糟。
func (r *LogRecorder) Stats() (written, dropped int64) {
	return r.written.Load(), r.dropped.Load()
}

func (r *LogRecorder) loop() {
	defer close(r.done)
	var since int
	for {
		select {
		case l := <-r.ch:
			r.write(l)
			if since++; since >= logPruneEvery {
				since = 0
				r.prune()
			}
		case <-r.stop:
			// 排空队列：已经采集到的日志没理由丢，尤其关闭前那几条
			// 往往正是导致关闭的那次故障的现场。
			for {
				select {
				case l := <-r.ch:
					r.write(l)
				default:
					r.prune()
					return
				}
			}
		}
	}
}

func (r *LogRecorder) write(l *model.RequestLog) {
	if err := r.w.InsertRequestLog(l); err != nil {
		// 只记日志，不重试：重试会让积压更严重，而日志本身是可丢的。
		r.log.Error("请求日志落库失败", "err", err, "req_id", l.ReqID)
		return
	}
	r.written.Add(1)
}

func (r *LogRecorder) prune() {
	keepCount, keepDays := defaultLogRetention()
	if r.retention != nil {
		s, err := r.retention.Settings()
		if err != nil {
			// 读不到就按默认值清，不能不清 —— 跳过的话，配置源出问题的
			// 那段时间日志会无上限堆积，而它正是最需要留出磁盘的时候。
			r.log.Warn("读取日志保留策略失败，按默认值清理", "err", err)
		} else {
			keepCount, keepDays = s.RequestLogKeepCount, s.RequestLogKeepDays
		}
	}

	n, err := r.w.PruneRequestLogs(keepCount, keepDays)
	if err != nil {
		r.log.Error("清理请求日志失败", "err", err)
		return
	}
	if n > 0 {
		r.log.Debug("已清理过期请求日志", "deleted", n)
	}
}

func defaultLogRetention() (keepCount, keepDays int) {
	d := model.DefaultSettings()
	return d.RequestLogKeepCount, d.RequestLogKeepDays
}

// Close 停止后台 writer 并等它排空队列。
func (r *LogRecorder) Close() {
	r.stopOnce.Do(func() { close(r.stop) })
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		r.log.Warn("请求日志 writer 未在 5 秒内收尾，放弃等待",
			"pending", len(r.ch))
	}
}

// reqIDEncoding 去掉 base32 的填充：req_id 会出现在 URL 查询参数里，
// 而 '=' 在那个位置需要转义 —— 一个不需要转义的 id 少一类 bug。
var reqIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewReqID 生成一个请求 id，把同一次客户端请求的多次尝试串起来。
//
// 用随机而不是自增：自增要先查库（或加全局锁），而这个函数跑在**转发路径上**，
// 每个请求一次 —— 一次 I/O 或一次锁竞争都不该出现在那里。
//
// 80 bit 随机。生日碰撞在 300 条（默认保留量）乃至百万行的规模下都远低于
// 任何其它出错概率，而更长的 id 只是让 UI 上那一列更难读。
//
// 不用 UUID：多一个依赖，且 36 字符带连字符的形式在列表页里占的宽度
// 是这里的两倍多。不用时间戳前缀：日志已有 ts_recv，重复一遍没有收益，
// 反而让 id 泄露了写入速率。
func NewReqID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败在实践中意味着系统熵源坏了。日志的 req_id
		// 不是安全边界（它只用来归组），退回时间戳足以保持可用 ——
		// 而让转发因为「生成不了日志 id」而失败是荒谬的主次倒置。
		return "ts-" + strings.ToLower(
			reqIDEncoding.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano))))
	}
	return strings.ToLower(reqIDEncoding.EncodeToString(b[:]))
}
