package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
		maxScope:  32,
		maxGlobal: 256,
		store:     store,
	}
}

// ObserveSuccessful 只接收正常成功与已 sanitizer 的 shape。
func (l *Learner) ObserveSuccessful(ctx context.Context, upstreamID int64, endpoint model.EndpointKind, shape model.ClientRequestShape) error {
	if l == nil {
		return nil
	}
	hash := ShapeHash(shape)
	if hash == "" {
		return nil
	}
	scope := fmt.Sprintf("%d:%s", upstreamID, endpoint)
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.byShape[hash]; ok {
		existing.SeenCount++
		return nil
	}
	if l.perScope[scope] >= l.maxScope || l.global >= l.maxGlobal {
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
		ShapeHash:      hash,
		Revision:       1,
		SeenCount:      1,
	}
	l.byShape[hash] = profile
	l.perScope[scope]++
	l.global++
	if l.store != nil {
		return l.store.UpsertClientProbeProfile(ctx, profile)
	}
	return nil
}

// ShapeHash 对排序规范化后的安全 shape 做带域 SHA-256。
func ShapeHash(shape model.ClientRequestShape) string {
	h := sha256.New()
	_, _ = h.Write([]byte("relay-gate:client-shape:v1\n"))
	_, _ = h.Write([]byte(shape.FixedRawQuery))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(shape.QueryShapeJSON)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(shape.BodyShapeJSON)
	_, _ = h.Write([]byte{0})
	for _, hdr := range shape.SafeHeaders {
		_, _ = h.Write([]byte(hdr.Name))
		_, _ = h.Write([]byte{0})
		for _, v := range hdr.Values {
			_, _ = h.Write([]byte(v))
			_, _ = h.Write([]byte{0})
		}
	}
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
			l.global -= l.perScope[scope]
			if l.global < 0 {
				l.global = 0
			}
			delete(l.perScope, scope)
		}
	}
}

