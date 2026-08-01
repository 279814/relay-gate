package api

import "net/http"

// runtimeInfo 是运行时观测数据：内存里的、重启即清零的那部分状态。
//
// 与 /admin/api/state 的区别：那个是「服务开关」（持久化的用户意图），
// 这个是「此刻正在发生什么」。
type runtimeInfo struct {
	// InFlight 是每个 Route 当前的在途请求数，只含非零项。
	// 配了 max_concurrency 的 Route 出现「一直选不中」时，先看这里 ——
	// 计数没归零就是额度泄漏，归零了就是别的原因。
	InFlight map[int64]int `json:"in_flight"`

	// SamplesWritten / SamplesDropped 见 §3.6.3a。
	//
	// dropped 必须能在界面上看到：样本队列打满时是**静默**丢弃的
	// （宁可丢样本也不阻塞转发），只写日志的话，「样本怎么少了几条」
	// 会变成一个无从下手的疑问 —— 而它其实有确切答案。
	SamplesWritten int64 `json:"samples_written"`
	SamplesDropped int64 `json:"samples_dropped"`

	// RequestLogs* 是请求日志的落库/丢弃计数（M6）。
	//
	// dropped 在这里比样本更要紧：丢掉的日志会让重试统计**偏低**
	// （分母少了几次请求），而那个统计正是用来决定「要不要保留重试」的。
	// 一个不知道自己不准的数字比没有数字更糟 —— 后者至少不会误导决策。
	RequestLogsWritten int64 `json:"request_logs_written"`
	RequestLogsDropped int64 `json:"request_logs_dropped"`
}

func (s *Server) getRuntime(w http.ResponseWriter, r *http.Request) {
	out := runtimeInfo{InFlight: map[int64]int{}}
	if s.inFlight != nil {
		out.InFlight = s.inFlight.Snapshot()
	}
	if s.samples != nil {
		out.SamplesWritten, out.SamplesDropped = s.samples.Stats()
	}
	if s.reqLogs != nil {
		out.RequestLogsWritten, out.RequestLogsDropped = s.reqLogs.Stats()
	}
	writeJSON(w, http.StatusOK, out)
}
