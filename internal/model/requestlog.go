package model

// RequestLog 是**一次尝试**的日志（M6，§3.5）。
//
// 与 Sample 的分工：Sample 存「发出去的到底是哪些字节」（三份 body + 三组头，
// 一次客户端请求一条，记的是最终那次尝试）；RequestLog 存「这次请求经历了
// 什么」（一次尝试一行，含被丢弃的那些）。
//
// 为什么不合并进 Sample：Sample 可以关、队列满会丢、按条数滚动清理 ——
// 从一个会丢、可关的数据源算成功率会得到一个**骗人的数字**。而这个类型
// 存在的全部理由就是回答「重试到底有没有用」。
//
// 刻意**不含任何 body 与头**：那是 Sample 的职责。重复存一份只会让磁盘
// 翻倍，还多一处需要脱敏的地方 —— 而漏一处就是明文 key 落库。
type RequestLog struct {
	ID int64 `json:"id"`

	// ReqID 把同一次客户端请求的多次尝试串起来。
	ReqID string `json:"req_id"`
	// Attempt 从 1 开始。Attempts 是这次客户端请求总共试了几次。
	Attempt  int `json:"attempt"`
	Attempts int `json:"attempts"`

	TSRecv      int64 `json:"ts_recv"`
	TSSent      int64 `json:"ts_sent"`
	TSFirstByte int64 `json:"ts_first_byte"`
	TSDone      int64 `json:"ts_done"`

	Endpoint    string `json:"endpoint"`
	ModelIn     string `json:"model_in"`
	ModelOut    string `json:"model_out"`
	ModelNameID int64  `json:"model_name_id"`
	RouteID     int64  `json:"route_id"`
	UpstreamID  int64  `json:"upstream_id"`
	// UpstreamName 冗余存一份：站被删掉之后，日志仍要能说清当时走的是哪个站。
	UpstreamName string `json:"upstream_name"`

	RespStatus   int   `json:"resp_status"`
	TTFTMs       int64 `json:"ttft_ms"`
	BytesWritten int64 `json:"bytes_written"`

	Outcome Outcome `json:"outcome"`
	// Retried 表示这次尝试被丢弃并换了站。
	//
	// 不等于 Outcome != ok：最后一次尝试失败时同样是失败，但没有被重试
	// （次数用尽、无站可换、或本就不可重试）。区分这两者才能回答
	// 「重试有没有救回来」—— 而那是这张表存在的理由。
	Retried bool `json:"retried"`
	// HalfOpen 标记半开放行的试探（§4.4c）。它的失败预期就高，
	// 混进成功率会拉低整体数字，让人误以为站的质量在下降。
	HalfOpen bool   `json:"half_open"`
	Error    string `json:"error"`
}

// TTFT 返回首 Token 延迟的毫秒数。未测到时为 0。
//
// 存成字段而不是每次由时间戳算：日志列表页要按它排序与展示，
// 而 ts_first_byte 为 0（没收到首字节）时相减会得到一个巨大的负数。
func (r *RequestLog) TTFT() int64 { return r.TTFTMs }

// Succeeded 表示这次尝试拿到了可用的响应。
//
// 判据是 outcome，不是状态码：一个 200 但零字节的「假活」响应
// （§4.3）状态码正常，却完全不可用。
func (r *RequestLog) Succeeded() bool { return r.Outcome == OutcomeOK }
