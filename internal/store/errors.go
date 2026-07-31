package store

import (
	"fmt"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// wrapConstraint 把 SQLite 的约束冲突翻译成人能看懂的、且 API 层能判 400 的错误。
//
// 驱动原文形如 "constraint failed: UNIQUE constraint failed: upstream.name (2067)"，
// 直接抛给用户既看不懂也不知道该改哪个字段。
func wrapConstraint(err error, table string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if !strings.Contains(msg, "constraint failed") {
		return err
	}

	switch {
	case strings.Contains(msg, "model_name.name"):
		return fmt.Errorf("%w: 该 ModelName 名称已存在", model.ErrValidation)
	case strings.Contains(msg, "upstream.name"):
		return fmt.Errorf("%w: 该 Upstream 名称已存在", model.ErrValidation)
	case strings.Contains(msg, "idx_model_name_fallback_per_protocol"),
		strings.Contains(msg, "model_name.protocol"):
		return fmt.Errorf("%w: 该协议已经有一个兜底 ModelName（is_fallback）了，"+
			"每种协议只能有一个。请先取消原有的兜底设置", model.ErrValidation)
	case strings.Contains(msg, "route.model_name_id") ||
		strings.Contains(msg, "idx_route") ||
		strings.Contains(msg, "route.upstream_id"):
		return fmt.Errorf("%w: 该 ModelName 与 Upstream 已经绑定过了，"+
			"同一组合只能有一条 Route（改优先级请编辑已有的那条）", model.ErrValidation)
	case strings.Contains(msg, "FOREIGN KEY"):
		return fmt.Errorf("%w: 引用的 ModelName 或 Upstream 不存在", model.ErrValidation)
	}
	return fmt.Errorf("%w: %s 约束冲突: %v", model.ErrValidation, table, err)
}
