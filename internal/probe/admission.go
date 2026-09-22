package probe

import (
	"context"
	"errors"

	"github.com/279814/relay-gate/internal/model"
)

// SyntheticAdmission 在合成探活写出请求之前占一个名额。
//
// P0-09 只用 AlwaysOpenAdmission：名额始终有，只为了把「占坑 / 释放」
// 这条调用顺序先钉在 Executor 上。P0-12 会换成进程级 Coordinator，
// 到那时拒绝或暂停必须仍然是零发送。真实流量不占这个名额。
type SyntheticAdmission interface {
	AcquireSynthetic(ctx context.Context, trigger model.ProbeTrigger) (attemptCtx context.Context, release func(), err error)
}

// ErrRealTrafficNoLease 表示有人想给真实流量占合成探活的名额。
//
// 真实请求的序号可以失败后直接跳过观察，但不能为了探活配额去等。
// 如果这里默默返回成功，P0-12 换成有上限的 Coordinator 时，
// 真实流量就会开始跟探活抢同一个坑。
var ErrRealTrafficNoLease = errors.New("real traffic does not take a synthetic probe lease")

// AlwaysOpenAdmission 不拒绝、不取消。release 可以重复调用，第二次是空操作。
func AlwaysOpenAdmission() SyntheticAdmission { return alwaysOpenAdmission{} }

type alwaysOpenAdmission struct{}

func (alwaysOpenAdmission) AcquireSynthetic(ctx context.Context, trigger model.ProbeTrigger) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !trigger.Valid() {
		return nil, nil, errors.New("synthetic admission trigger 无效")
	}
	if trigger == model.TriggerRealTraffic {
		return nil, nil, ErrRealTrafficNoLease
	}
	return ctx, func() {}, nil
}
