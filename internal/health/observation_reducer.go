package health

// ObservationReducer 是 CommitProbeObservation 注入的纯状态转换（§4.8）。
//
// 它不做 I/O、不读时钟以外的全局状态、不持有事务外引用：Store 在事务内
// 锁定 current row、校验 expectation/order 之后才调用它，并把返回值落库。
// 阈值、TTL、错误分类和状态转换都在这里；Store 不得自行承载探活业务规则。

import (
	"fmt"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observation"
)

// ObservationReducer 满足 observation.StateReducer。
type ObservationReducer struct {
	now func() time.Time
}

// NewObservationReducer 构造生产用 reducer。now 为 nil 时用 time.Now。
func NewObservationReducer(now func() time.Time) *ObservationReducer {
	if now == nil {
		now = time.Now
	}
	return &ObservationReducer{now: now}
}

var _ observation.StateReducer = (*ObservationReducer)(nil)

// ReduceReachability 按 execution 的可达性结论推进站级状态。
//
// 任意合法 HTTP 响应（含 401/404/429/503）都算 reachable；只有拿不到响应头
// 才是 unreachable（§8.9）。阶段耗时从 SentAt/TLS/GotConn/ResponseHeader/DoneAt
// 重建；复用连接 TLS=0；非法阶段次序归零且只记受限诊断。
func (reducer *ObservationReducer) ReduceReachability(current *model.UpstreamReachability,
	execution model.ProbeExecution, policy model.ReachabilityReductionPolicy) (*model.UpstreamReachability, error) {

	if policy.ReachableThreshold <= 0 || policy.UnreachableThreshold <= 0 {
		return nil, fmt.Errorf("reachability 阈值必须为正：ok=%d fail=%d",
			policy.ReachableThreshold, policy.UnreachableThreshold)
	}

	next := &model.UpstreamReachability{}
	if current != nil {
		*next = *current
	}

	connectMS, tlsMS, headerMS, stageDiag := stageLatenciesMS(execution)
	next.LastConnectMS = connectMS
	next.LastTLSMS = tlsMS
	next.LastHeaderMS = headerMS

	nowMS := reducer.now().UnixMilli()
	if execution.Reachable {
		next.ConsecutiveOK++
		next.ConsecutiveFail = 0
		next.LastOKAt = nowMS
		next.LastError = ""
		if next.ConsecutiveOK >= policy.ReachableThreshold || next.State == "" ||
			next.State == model.ReachabilityUnknown || next.State == model.ReachabilityUnreachable {
			// 首次可达或达阈值后进入 reachable。unknown→reachable 允许在阈值=1
			// 时立即生效；阈值>1 时仍累计，但首次成功至少离开 unreachable。
			if next.ConsecutiveOK >= policy.ReachableThreshold {
				next.State = model.ReachabilityReachable
			} else if next.State != model.ReachabilityReachable {
				next.State = model.ReachabilityUnknown
			}
		}
	} else {
		next.ConsecutiveFail++
		next.ConsecutiveOK = 0
		next.LastErrorAt = nowMS
		next.LastError = reachabilityErrorDetail(execution, stageDiag)
		if next.ConsecutiveFail >= policy.UnreachableThreshold {
			next.State = model.ReachabilityUnreachable
		} else if next.State == "" {
			next.State = model.ReachabilityUnknown
		}
	}
	if next.State == "" {
		next.State = model.ReachabilityUnknown
	}
	return next, nil
}

// ReduceCapability 按 execution 的 Capability 结论推进端点能力行。
//
// 五态只持久化 unknown/supported/unsupported/transient_error/config_error；
// 过期由 ExpiresAt <= now 派生，不写第六种 stale。本 reducer **永不**写
// RouteHealth（§P0-10 验收第 19 条）。
func (reducer *ObservationReducer) ReduceCapability(current *model.EndpointCapability,
	execution model.ProbeExecution, policy model.CapabilityReductionPolicy) (*model.EndpointCapability, error) {

	if execution.ErrorClass == model.ErrorIgnored {
		// 客户端取消 / 暂停 / 关闭：能力行完全不动。
		if current == nil {
			return &model.EndpointCapability{State: model.CapabilityUnknown}, nil
		}
		copyValue := *current
		return &copyValue, nil
	}

	state := execution.Capability
	if state == "" {
		state = model.CapabilityUnknown
	}
	if !state.Valid() {
		return nil, fmt.Errorf("capability state 无效: %q", state)
	}

	next := &model.EndpointCapability{}
	if current != nil {
		*next = *current
	}
	nowMS := reducer.now().UnixMilli()
	next.State = state
	next.ObservedAt = nowMS
	next.StatusCode = execution.StatusCode
	next.ErrorClass = execution.ErrorClass
	next.RedactedDetail = execution.RedactedDetail
	next.ResolvedURLHash = execution.ResolvedURLHash
	next.ExpiresAt = capabilityExpiresAt(state, nowMS, execution.RetryAfterUntilMS, policy)

	if execution.Trigger == model.TriggerRealTraffic && execution.Success {
		next.LastRealOKAt = nowMS
		next.LastRealOKToken = execution.CapabilityToken
	}
	return next, nil
}

func capabilityExpiresAt(state model.CapabilityState, nowMS, retryAfterUntilMS int64,
	policy model.CapabilityReductionPolicy) int64 {

	switch state {
	case model.CapabilitySupported:
		if policy.SupportedTTL <= 0 {
			return 0
		}
		return nowMS + policy.SupportedTTL.Milliseconds()
	case model.CapabilityUnsupported:
		if policy.UnsupportedTTL <= 0 {
			return 0
		}
		return nowMS + policy.UnsupportedTTL.Milliseconds()
	case model.CapabilityTransientError:
		if retryAfterUntilMS > nowMS {
			return retryAfterUntilMS
		}
		if policy.TransientTTL <= 0 {
			return 0
		}
		return nowMS + policy.TransientTTL.Milliseconds()
	case model.CapabilityConfigError:
		// config_error 只由语义配置变化或人工测试解除，不设自动过期。
		return 0
	default:
		return 0
	}
}

func reachabilityErrorDetail(execution model.ProbeExecution, stageDiag string) string {
	if stageDiag != "" {
		return stageDiag
	}
	if execution.RedactedDetail != "" {
		return execution.RedactedDetail
	}
	if execution.ErrorClass != "" && execution.ErrorClass != model.ErrorNone {
		return string(execution.ErrorClass)
	}
	return "unreachable"
}

// stageLatenciesMS 从阶段时间戳重建 LastConnectMS/LastTLSMS/LastHeaderMS。
//
// 规则（§P0-10 第 2 条）：
//   - Connect：GotConn - SentAt；GotConn 前失败则用 DoneAt - SentAt
//   - TLS：Done - Start；复用连接（无 TLS 时刻）为 0
//   - Header：ResponseHeader - GotConn（无 GotConn 时用 SentAt）
//   - 任一负值或非法次序 → 三端归零，返回受限诊断
func stageLatenciesMS(execution model.ProbeExecution) (connectMS, tlsMS, headerMS int64, diag string) {
	sent := execution.SentAtMS
	if sent <= 0 {
		return 0, 0, 0, ""
	}
	gotConn := execution.GotConnAtMS
	tlsStart := execution.TLSHandshakeStartAtMS
	tlsDone := execution.TLSHandshakeDoneAtMS
	headerAt := execution.ResponseHeaderAtMS
	done := execution.DoneAtMS

	if gotConn > 0 {
		connectMS = gotConn - sent
	} else if done > 0 {
		connectMS = done - sent
	}
	if tlsStart > 0 && tlsDone > 0 {
		tlsMS = tlsDone - tlsStart
	}
	if headerAt > 0 {
		base := gotConn
		if base <= 0 {
			base = sent
		}
		headerMS = headerAt - base
	}

	if connectMS < 0 || tlsMS < 0 || headerMS < 0 {
		return 0, 0, 0, "stage_order_invalid"
	}
	if tlsStart > 0 && tlsDone > 0 && tlsDone < tlsStart {
		return 0, 0, 0, "stage_order_invalid"
	}
	if gotConn > 0 && sent > 0 && gotConn < sent {
		return 0, 0, 0, "stage_order_invalid"
	}
	if headerAt > 0 && gotConn > 0 && headerAt < gotConn {
		return 0, 0, 0, "stage_order_invalid"
	}
	return connectMS, tlsMS, headerMS, ""
}
