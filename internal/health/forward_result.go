package health

import "errors"

var (
	ErrConnect           = errors.New("连接上游失败")
	ErrFirstTokenTimeout = errors.New("首 Token 超时")
	ErrStreamStalled     = errors.New("流内静默超时")
	ErrTotalTimeout      = errors.New("超过总时限")
	ErrUpstreamBroke     = errors.New("上游未返回任何数据即断开")
	ErrStreamBroke       = errors.New("流式传输中途断开")
	ErrClientGone        = errors.New("客户端已断开")
	ErrCanceled          = errors.New("请求被取消")
)

func IsUpstreamFault(err error) bool {
	return err != nil && !errors.Is(err, ErrClientGone) && !errors.Is(err, ErrCanceled)
}
