package probe

import (
	"sync"
	"time"
)

// Timer 是一次阶段预算。
//
// 探活要同时守住响应头、首字节、首事件、首语义、空闲和外层总时长。
// 这些计时必须能在测试里拨快，否则「慢语义」只能靠真的睡过去，
// 而长思考的下限是 5 分钟，测试会变得不能跑。
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// Clock 是 Executor 唯一允许看见的时间来源。
//
// Classifier 已经禁止自己读挂钟（Retry-After 用注入的 headerAt）。
// 执行器若再偷偷调用 time.Now，阶段耗时和那份绝对时间就会各算各的。
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

// WallClock 使用进程的真实挂钟。生产装配用它，测试用 ManualClock。
func WallClock() Clock { return wallClock{} }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) NewTimer(d time.Duration) Timer {
	return wallTimer{timer: time.NewTimer(d)}
}

type wallTimer struct{ timer *time.Timer }

func (t wallTimer) C() <-chan time.Time { return t.timer.C }

func (t wallTimer) Stop() bool { return t.timer.Stop() }

func (t wallTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }

// ManualClock 按测试拨动的时间触发定时器，不跟挂钟走。
type ManualClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*manualTimer
}

// NewManualClock 从给定时刻开始。零值时刻也可以，测试只关心相对推进。
func NewManualClock(now time.Time) *ManualClock {
	return &ManualClock{now: now}
}

func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ManualClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &manualTimer{
		clock: c,
		when:  c.now.Add(d),
		ch:    make(chan time.Time, 1),
	}
	c.timers = append(c.timers, timer)
	timer.fireLocked(c.now)
	return timer
}

// Advance 把时钟向前拨，并触发所有到期且仍有效的定时器。
// 往回拨什么都不触发：阶段超时不能因为测试把时钟拨回去就消失，
// 已经过去的截止时间也不会再次响。
func (c *ManualClock) Advance(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, timer := range c.timers {
		timer.fireLocked(c.now)
	}
}

type manualTimer struct {
	clock   *ManualClock
	when    time.Time
	ch      chan time.Time
	fired   bool
	stopped bool
}

func (t *manualTimer) C() <-chan time.Time { return t.ch }

func (t *manualTimer) fireLocked(now time.Time) {
	if t.fired || t.stopped || now.Before(t.when) {
		return
	}
	t.fired = true
	t.ch <- now
}

func (t *manualTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.fired || t.stopped {
		return false
	}
	t.stopped = true
	return true
}

func (t *manualTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := !t.fired && !t.stopped
	t.fired = false
	t.stopped = false
	t.when = t.clock.now.Add(d)
	t.fireLocked(t.clock.now)
	return active
}
