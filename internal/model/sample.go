package model

import "net/http"

// Outcome 是一次转发的结果分类（§3.6.2）。
type Outcome string

const (
	OutcomeOK Outcome = "ok"
	// OutcomeUpstreamError 覆盖连不上、4xx/5xx、中途断流。
	OutcomeUpstreamError Outcome = "upstream_error"
	OutcomeTimeout       Outcome = "timeout"
	// OutcomeFakeAlive 是 200 但一个字节都没吐的站 —— 看起来活着，实际不可用。
	// 单独分类是因为它最容易被误判成好站（§4.3）。
	OutcomeFakeAlive Outcome = "fake_alive"
	// OutcomeClientAbort 是客户端主动断开或取消，不是上游的问题。
	OutcomeClientAbort Outcome = "client_abort"
)

// Valid 用于筛选参数校验：写错的 outcome 应该报错，
// 而不是安静地返回一个空列表 —— 那看起来像「这段时间没有请求」。
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeOK, OutcomeUpstreamError, OutcomeTimeout,
		OutcomeFakeAlive, OutcomeClientAbort:
		return true
	}
	return false
}

// TruncFlags 是位标记，说明样本里哪些字段被截断了（§3.6.2 的 truncated 列）。
//
// 必须记下来：不标记的话，看到一个 256KB 整的 body 无法判断它是恰好这么大
// 还是被砍过 —— 而这会让「验证只改了两处」的比对得出错误结论。
type TruncFlags int

const (
	TruncInBody TruncFlags = 1 << iota
	TruncOutBody
	TruncRespBody
)

func (f TruncFlags) Has(x TruncFlags) bool { return f&x != 0 }

// Sample 是一次转发的完整留档（§3.6）。
//
// 三份内容：入站原始请求、实际发往公益站的请求、公益站的返回。
// body 一律是**原始字节**，不是重新序列化的 JSON —— 整个功能的意义就在于
// 「发出去的到底是哪些字节」，转一道就失去了价值。
type Sample struct {
	ID int64 `json:"id"`

	// ReqID 与 RequestLog 同组，便于从样本跳到「这次请求试过哪几个站」
	// （反向亦然）。空串表示这条样本早于 M6，或请求日志被关掉了。
	//
	// 关联方向是「样本存 req_id」而不是「日志存 sample_id」：样本 id 由
	// 后台 writer 落库时才分配，而日志在转发路径上就要写出去 —— 那一刻
	// sample_id 还不存在。req_id 则是请求开始时生成的，两边同步可知。
	ReqID string `json:"req_id"`

	// 四个时间戳（Unix 毫秒）。差值即排队时长、TTFT、总时长。
	TSRecv      int64 `json:"ts_recv"`
	TSSent      int64 `json:"ts_sent"`
	TSFirstByte int64 `json:"ts_first_byte"`
	TSDone      int64 `json:"ts_done"`

	Endpoint string `json:"endpoint"`
	// ModelIn 是入站 model 值，ModelOut 是映射后的值（未映射时两者相同）。
	ModelIn     string `json:"model_in"`
	ModelOut    string `json:"model_out"`
	ModelNameID int64  `json:"model_name_id"`
	RouteID     int64  `json:"route_id"`
	UpstreamID  int64  `json:"upstream_id"`

	InMethod string `json:"in_method"`
	InPath   string `json:"in_path"`
	// InQuery 是 RawQuery。?beta=true 在这里，丢了会改变上游行为。
	InQuery   string      `json:"in_query"`
	InHeaders http.Header `json:"in_headers"`
	InBody    []byte      `json:"in_body,omitempty"`

	OutURL     string      `json:"out_url"`
	OutHeaders http.Header `json:"out_headers"`
	OutBody    []byte      `json:"out_body,omitempty"`

	RespStatus  int         `json:"resp_status"`
	RespHeaders http.Header `json:"resp_headers"`
	RespBody    []byte      `json:"resp_body,omitempty"`

	Outcome   Outcome    `json:"outcome"`
	Error     string     `json:"error"`
	Truncated TruncFlags `json:"truncated"`
	// Pinned 的样本不参与滚动清理（§3.6.3c）。
	Pinned bool `json:"pinned"`
}
