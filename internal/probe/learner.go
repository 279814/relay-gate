package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"sync"

	"github.com/279814/relay-gate/internal/model"
)

// Learner 把已脱敏的 ClientRequestShape 收成 candidate profile。
type Learner struct {
	mu        sync.Mutex
	byShape   map[string]*model.ClientProbeProfile
	perScope  map[string]int
	global    int
	maxScope  int
	maxGlobal int
	store     LearnerStore
}

// LearnerStore 持久化 candidate（可选）。
type LearnerStore interface {
	UpsertClientProbeProfile(ctx context.Context, profile *model.ClientProbeProfile) error
}

// NewLearner 构造有界 Learner。
func NewLearner(store LearnerStore) *Learner {
	return &Learner{
		byShape:   map[string]*model.ClientProbeProfile{},
		perScope:  map[string]int{},
		maxScope:  model.ClientProfileScopeLimit,
		maxGlobal: model.ClientProfileGlobalLimit,
		store:     store,
	}
}

// ObserveSuccessful 只接收正常成功与已 sanitizer 的 shape。
//
// §8.4：不得保存认证值。入站 shape 仍可能带 Authorization / X-Api-Key /
// Api-Key、Cookie 里的 relay_session、或纯凭据 query —— 在入库前再剥一层，
// 不信任上游 sanitizer 已做完。安全协议头（如 anthropic-beta）保留。
func (l *Learner) ObserveSuccessful(ctx context.Context, upstreamID int64, endpoint model.EndpointKind, shape model.ClientRequestShape) error {
	if l == nil {
		return nil
	}
	var err error
	shape, err = sanitizeLearnedShape(endpoint, shape)
	if err != nil {
		return err
	}
	hash := ShapeHash(shape)
	if hash == "" {
		return nil
	}
	profile := &model.ClientProbeProfile{
		UpstreamID:     upstreamID,
		Endpoint:       endpoint,
		Status:         model.ProfileCandidate,
		SafeHeaders:    shape.SafeHeaders,
		FixedRawQuery:  shape.FixedRawQuery,
		QueryShapeJSON: append([]byte(nil), shape.QueryShapeJSON...),
		BodyTemplate:   append([]byte(nil), shape.BodyTemplate...),
		BodyShapeJSON:  append([]byte(nil), shape.BodyShapeJSON...),
		ClientFamily:   shape.ClientFamily,
		ShapeHash:      hash,
		Revision:       1,
		SeenCount:      1,
	}
	if l.store != nil {
		// SQLite owns bounds, identity and telemetry across process restarts.
		// A failed write must not poison a separate in-memory deduplication cache.
		return l.store.UpsertClientProbeProfile(ctx, profile)
	}
	scope := fmt.Sprintf("%d:%s:%s", upstreamID, endpoint, shape.ClientFamily)
	key := scope + ":" + hash
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.byShape[key]; ok {
		existing.SeenCount++
		return nil
	}
	upstreamCount := 0
	for _, candidate := range l.byShape {
		if candidate.UpstreamID == upstreamID {
			upstreamCount++
		}
	}
	if l.perScope[scope] >= l.maxScope || upstreamCount >= model.ClientProfileUpstreamLimit || l.global >= l.maxGlobal {
		return model.ErrClientProfileCapacity
	}
	l.byShape[key] = profile
	l.perScope[scope]++
	l.global++
	return nil
}

// materializeLearnedBodyTemplate 生成该端点的紧凑探活 body（§8.4）。
//
// 与内置 compact 模板同形：model / 输出上限 / stream（若适用）+ 单条
// {{PROBE_PROMPT}}，不含 system、tools、metadata、客户端 messages 原文或
// 认证值。入站 BodyTemplate 一律忽略，避免把真实流量 JSON 拷进探活。
func materializeLearnedBodyTemplate(endpoint model.EndpointKind) []byte {
	switch endpoint {
	case model.EndpointModels:
		return nil
	case model.EndpointMessages:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"{{PROBE_PROMPT}}"}]}]}`)
	case model.EndpointCountTokens:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","messages":[{"role":"user","content":[{"type":"text","text":"{{PROBE_PROMPT}}"}]}]}`)
	case model.EndpointChatCompletions:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","messages":[{"role":"user","content":"{{PROBE_PROMPT}}"}],"max_tokens":1,"stream":true}`)
	case model.EndpointResponses:
		return []byte(`{"model":"{{UPSTREAM_MODEL}}","input":[{"role":"user","content":[{"type":"input_text","text":"{{PROBE_PROMPT}}"}]}],"max_output_tokens":16,"stream":true}`)
	default:
		return nil
	}
}

// ShapeHash 对排序规范化后的安全 shape 做带域 SHA-256。
func ShapeHash(shape model.ClientRequestShape) string {
	canonical := func(raw []byte) (json.RawMessage, error) {
		if len(raw) == 0 {
			return json.RawMessage("null"), nil
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		return json.Marshal(value)
	}
	query, err := canonical(shape.QueryShapeJSON)
	if err != nil {
		return ""
	}
	body, err := canonical(shape.BodyShapeJSON)
	if err != nil {
		return ""
	}
	template, err := canonical(shape.BodyTemplate)
	if err != nil {
		return ""
	}
	headers := canonicalShapeHeaders(shape.SafeHeaders)
	queryValues, err := url.ParseQuery(shape.FixedRawQuery)
	if err != nil {
		return ""
	}
	for name := range queryValues {
		sort.Strings(queryValues[name])
	}
	encoded, err := json.Marshal(struct {
		Family                          string
		Headers                         []model.HeaderTemplate
		Query                           string
		QueryShape, BodyShape, Template json.RawMessage
	}{shape.ClientFamily, headers, queryValues.Encode(), query, body, template})
	if err != nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte("relay-gate:client-shape:v2\n"))
	_, _ = h.Write(encoded)
	return hex.EncodeToString(h.Sum(nil))
}

// ForgetUpstream drops in-memory learned shapes for one Upstream (§9.2).
func (l *Learner) ForgetUpstream(upstreamID int64) {
	if l == nil || upstreamID <= 0 {
		return
	}
	prefix := fmt.Sprintf("%d:", upstreamID)
	l.mu.Lock()
	defer l.mu.Unlock()
	for hash, profile := range l.byShape {
		if profile != nil && profile.UpstreamID == upstreamID {
			delete(l.byShape, hash)
			l.global--
		}
	}
	for scope := range l.perScope {
		if len(scope) >= len(prefix) && scope[:len(prefix)] == prefix {
			delete(l.perScope, scope)
		}
	}
}
