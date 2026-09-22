package observationseq

import (
	"context"
	"errors"
	"sync"

	"github.com/279814/relay-gate/internal/model"
)

const (
	// BlockSize 是一次从数据库预留的序号个数。
	//
	// 序号先落库再分配。进程在用完一块之前崩溃，没用到的号就留下空档，
	// 重启后的下一块从 high watermark 之后开始。空档可以有，复用不行：
	// 复用会让一条旧的慢失败带着和新的成功一样的 order 回来。
	BlockSize int64 = 4096

	// LowWater 是还剩这么多个号时就开始预留下一块。
	//
	// 预留要写 SQLite。如果等到当前块用尽再去写，合成探活会停在写库上，
	// 真实请求则会直接丢掉这次观察。提前一块，正常情况下边界处已经有号。
	LowWater int64 = 512
)

// ErrUnavailable 表示这次拿不到序号，而且调用方不该为了它等待。
//
// 真实流量遇到它就跳过观察，请求本身继续。合成探活遇到它就不要发请求：
// 发出去却没有 order，这条结果以后无法和更新的结果比较先后。
var ErrUnavailable = errors.New("observation order unavailable")

// Reserver 原子预留一段还没人用过的序号。*store.Store 满足它。
type Reserver interface {
	ReserveObservationOrders(ctx context.Context, blockSize int64) (start, end int64, err error)
}

// Sequencer 只分配已经预留成功的序号。
type Sequencer struct {
	reserve Reserver
	base    context.Context

	mu          sync.Mutex
	cond        *sync.Cond
	next        int64
	end         int64
	pendingNext int64
	pendingEnd  int64
	hasPending  bool
	prefetching bool
	prefetchErr error
	closed      bool
}

// Open 先预留第一块。预留失败就拒绝启动：带着一个发不出序号的进程去听端口，
// 合成探活会全部在写 socket 之前失败，看起来像所有上游一起挂了。
func Open(ctx context.Context, reserve Reserver) (*Sequencer, error) {
	if ctx == nil {
		return nil, errors.New("observation sequencer 缺少生命周期 context")
	}
	if reserve == nil {
		return nil, errors.New("observation sequencer 缺少 reserver")
	}
	start, end, err := reserve.ReserveObservationOrders(ctx, BlockSize)
	if err != nil {
		return nil, err
	}
	if err := validBlock(start, end); err != nil {
		return nil, err
	}
	seq := &Sequencer{reserve: reserve, base: ctx, next: start, end: end}
	seq.cond = sync.NewCond(&seq.mu)
	return seq, nil
}

// Close 拒绝后续分配。已经在飞的预留可以留下空档，不能把号再发出来。
func (s *Sequencer) Close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Next 分配下一个序号。
//
// 真实流量在当前块和已预留的下一块都没有号时立刻返回 ErrUnavailable，
// 不等待正在进行的预留。合成探活可以等那次预留，但等不到就返回错误，
// 调用方必须把这次请求留在未发送。
func (s *Sequencer) Next(ctx context.Context, trigger model.ProbeTrigger) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !trigger.Valid() {
		return 0, errors.New("observation trigger 无效")
	}
	real := trigger == model.TriggerRealTraffic
	if !real && ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() {
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		})
		defer stop()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.closed || s.base.Err() != nil {
			return 0, ErrUnavailable
		}
		if order, ok := s.tryTakeLocked(); ok {
			return order, nil
		}
		if real {
			s.armIfIdleLocked()
			return 0, ErrUnavailable
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if s.prefetchErr != nil && !s.prefetching {
			err := s.prefetchErr
			s.prefetchErr = nil
			s.armIfIdleLocked()
			return 0, err
		}
		if !s.prefetching {
			s.armIfIdleLocked()
		}
		s.cond.Wait()
	}
}

func (s *Sequencer) tryTakeLocked() (int64, bool) {
	if s.next > s.end {
		if !s.hasPending {
			return 0, false
		}
		s.next, s.end = s.pendingNext, s.pendingEnd
		s.hasPending = false
		s.pendingNext, s.pendingEnd = 0, 0
	}
	order := s.next
	s.next++
	if s.end-s.next+1 <= LowWater {
		s.armIfIdleLocked()
	}
	return order, true
}

func (s *Sequencer) armIfIdleLocked() {
	if s.closed || s.base.Err() != nil || s.hasPending || s.prefetching {
		return
	}
	s.prefetching = true
	go s.prefetch()
}

func (s *Sequencer) prefetch() {
	start, end, err := s.reserve.ReserveObservationOrders(s.base, BlockSize)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefetching = false
	if s.closed || s.base.Err() != nil {
		s.cond.Broadcast()
		return
	}
	if err == nil {
		err = validBlock(start, end)
	}
	if err == nil && start <= s.end {
		err = errors.New("observation 序号块与已预留的号重叠")
	}
	if err != nil {
		s.prefetchErr = err
	} else {
		s.pendingNext, s.pendingEnd, s.hasPending = start, end, true
		s.prefetchErr = nil
	}
	s.cond.Broadcast()
}

func validBlock(start, end int64) error {
	if start <= 0 || end < start || end-start+1 != BlockSize {
		return errors.New("observation 序号块不合法")
	}
	return nil
}
