package revisioncodec

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const (
	observationTokenDomain   = "relay-gate/observation-token/v1"
	reachabilityTokenDomain  = "relay-gate/reachability-token/v1"
	secretRevisionDomain     = "relay-gate/secret-revision-set/v1"
	capabilityPolicyDomain   = "relay-gate/probe-settings/v1"
	reachabilityPolicyDomain = "relay-gate/reachability-settings/v1"
)

const (
	ParserPolicyVersion        = 1
	DefaultMaxEventBytes int64 = 1 << 20
	DefaultMaxTotalBytes int64 = 4 << 20
)

var defaultCapabilityReductionPolicy = model.CapabilityReductionPolicy{
	SupportedTTL:   10 * time.Minute,
	UnsupportedTTL: 30 * time.Minute,
	TransientTTL:   time.Minute,
}

func BuildCapabilityEvidencePolicy(settings model.Settings, selector model.EvidencePolicySelector) (model.CapabilityEvidencePolicy, error) {
	stages, err := stageBudget(settings, selector)
	if err != nil {
		return model.CapabilityEvidencePolicy{}, err
	}
	if selector.TimeoutProfile == model.TimeoutL2LongThink && stages.FirstSemantic < int64(model.MinRealFirstSemanticSec)*1000 {
		return model.CapabilityEvidencePolicy{}, model.WrapValidation(
			"l2_long_thinking first_semantic 不得低于 %d 秒", model.MinRealFirstSemanticSec)
	}
	return model.CapabilityEvidencePolicy{
		Selector:            selector,
		Stages:              stages,
		ParserPolicyVersion: ParserPolicyVersion,
		MaxEventBytes:       DefaultMaxEventBytes,
		MaxTotalBytes:       DefaultMaxTotalBytes,
		State:               defaultCapabilityReductionPolicy,
	}, nil
}

func BuildReachabilityEvidencePolicy(settings model.Settings, selector model.EvidencePolicySelector) (model.ReachabilityEvidencePolicy, error) {
	stages, err := stageBudget(settings, selector)
	if err != nil {
		return model.ReachabilityEvidencePolicy{}, err
	}
	return model.ReachabilityEvidencePolicy{
		Selector:         selector,
		ConnectMS:        stages.Connect,
		ResponseHeaderMS: stages.ResponseHeader,
		TotalMS:          stages.Total,
		State: model.ReachabilityReductionPolicy{
			ReachableThreshold:   settings.OKThreshold,
			UnreachableThreshold: settings.FailThreshold,
		},
	}, nil
}

func stageBudget(settings model.Settings, selector model.EvidencePolicySelector) (model.StageBudgetMS, error) {
	if err := selector.Validate(); err != nil {
		return model.StageBudgetMS{}, err
	}
	seconds := func(value int, name string) (int64, error) {
		if value <= 0 {
			return 0, model.WrapValidation("%s 必须为正数", name)
		}
		return int64(value) * 1000, nil
	}
	var values []struct {
		target *int64
		value  int
		name   string
	}
	var stages model.StageBudgetMS
	switch selector.Kind {
	case model.EvidenceL1:
		values = []struct {
			target *int64
			value  int
			name   string
		}{
			{&stages.Connect, settings.L1ConnectSec, "l1_connect_sec"},
			{&stages.ResponseHeader, settings.L1TotalSec, "l1_total_sec"},
			{&stages.Total, settings.L1TotalSec, "l1_total_sec"},
		}
	case model.EvidenceL2:
		values = []struct {
			target *int64
			value  int
			name   string
		}{
			{&stages.Connect, settings.L2ConnectSec, "l2_connect_sec"},
			{&stages.ResponseHeader, settings.L2ResponseHeaderSec, "l2_response_header_sec"},
			{&stages.FirstByte, settings.L2FirstByteSec, "l2_first_byte_sec"},
			{&stages.FirstEvent, settings.L2FirstEventSec, "l2_first_event_sec"},
			{&stages.FirstSemantic, settings.L2FirstSemanticSec, "l2_first_semantic_sec"},
			{&stages.Idle, settings.L2IdleSec, "l2_idle_sec"},
			{&stages.Total, settings.L2TotalSec, "l2_total_sec"},
		}
	case model.EvidenceCountTokens:
		values = []struct {
			target *int64
			value  int
			name   string
		}{
			{&stages.Connect, settings.CountTokensConnectSec, "count_tokens_connect_sec"},
			{&stages.ResponseHeader, settings.CountTokensTotalSec, "count_tokens_total_sec"},
			{&stages.Total, settings.CountTokensTotalSec, "count_tokens_total_sec"},
		}
	case model.EvidenceRealTraffic:
		values = []struct {
			target *int64
			value  int
			name   string
		}{
			{&stages.Connect, settings.RealConnectSec, "real_connect_sec"},
			{&stages.ResponseHeader, settings.RealResponseHeaderSec, "real_response_header_sec"},
			{&stages.FirstByte, settings.RealFirstByteSec, "real_first_byte_sec"},
			{&stages.FirstSemantic, settings.RealFirstSemanticSec, "real_first_semantic_sec"},
			{&stages.Idle, settings.RealIdleSec, "real_idle_sec"},
			{&stages.Total, settings.RealTotalSec, "real_total_sec"},
		}
	}
	for _, value := range values {
		milliseconds, err := seconds(value.value, value.name)
		if err != nil {
			return model.StageBudgetMS{}, err
		}
		*value.target = milliseconds
	}
	if stages.Connect > stages.Total || stages.ResponseHeader > stages.Total || stages.FirstByte > stages.Total ||
		stages.FirstEvent > stages.Total || stages.FirstSemantic > stages.Total {
		return model.StageBudgetMS{}, model.WrapValidation("阶段预算不能超过 total")
	}
	return stages, nil
}

func ProbeSettingsFingerprint(policy model.CapabilityEvidencePolicy) string {
	encoder := newCanonicalEncoder(capabilityPolicyDomain)
	encoder.selector(policy.Selector)
	encoder.stageBudget(policy.Stages)
	encoder.int64(int64(policy.ParserPolicyVersion))
	encoder.int64(policy.MaxEventBytes)
	encoder.int64(policy.MaxTotalBytes)
	encoder.int64(int64(policy.State.SupportedTTL))
	encoder.int64(int64(policy.State.UnsupportedTTL))
	encoder.int64(int64(policy.State.TransientTTL))
	return encoder.digest()
}

func ReachabilitySettingsFingerprint(policy model.ReachabilityEvidencePolicy) string {
	encoder := newCanonicalEncoder(reachabilityPolicyDomain)
	encoder.selector(policy.Selector)
	encoder.int64(policy.ConnectMS)
	encoder.int64(policy.ResponseHeaderMS)
	encoder.int64(policy.TotalMS)
	encoder.int64(int64(policy.State.ReachableThreshold))
	encoder.int64(int64(policy.State.UnreachableThreshold))
	return encoder.digest()
}

func NewObservationToken(revision model.SemanticRevision) string {
	encoder := newCanonicalEncoder(observationTokenDomain)
	encoder.int64(revision.UpstreamNetwork)
	encoder.int64(revision.UpstreamCredential)
	encoder.int64(revision.EndpointID)
	encoder.int64(revision.EndpointRevision)
	encoder.int64(revision.ModelCapability)
	encoder.int64(revision.RouteCapability)
	encoder.int64(revision.AuthProfile)
	encoder.recipeIdentity(revision.RecipeIdentity)
	encoder.int64(revision.RecipeBindingRevision)
	encoder.string(revision.ProbeSettingsFingerprint)
	encoder.secretRevisions(revision.ProbeSecrets)
	encoder.int64(revision.RequestTransform)
	return encoder.digest()
}

func NewReachabilityToken(revision model.ReachabilityRevision) string {
	encoder := newCanonicalEncoder(reachabilityTokenDomain)
	encoder.int64(revision.NetworkRevision)
	encoder.string(revision.SettingsFingerprint)
	return encoder.digest()
}

func SecretRevisionSetHash(revisions []model.SecretRevision) string {
	encoder := newCanonicalEncoder(secretRevisionDomain)
	encoder.secretRevisions(revisions)
	return encoder.digest()
}

type canonicalEncoder struct {
	content []byte
}

func newCanonicalEncoder(domain string) *canonicalEncoder {
	encoder := &canonicalEncoder{}
	encoder.string(domain)
	return encoder
}

func (encoder *canonicalEncoder) uint32(value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	encoder.content = append(encoder.content, encoded[:]...)
}

func (encoder *canonicalEncoder) int64(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	encoder.content = append(encoder.content, encoded[:]...)
}

func (encoder *canonicalEncoder) string(value string) {
	encoder.uint32(uint32(len(value)))
	encoder.content = append(encoder.content, value...)
}

func (encoder *canonicalEncoder) boolean(value bool) {
	if value {
		encoder.content = append(encoder.content, 1)
		return
	}
	encoder.content = append(encoder.content, 0)
}

func (encoder *canonicalEncoder) recipeIdentity(identity model.RecipeIdentity) {
	encoder.string(string(identity.Storage))
	encoder.string(string(identity.Origin))
	encoder.int64(identity.DBVersionID)
	encoder.int64(identity.ClientProfileID)
	encoder.string(identity.TemplateID)
	encoder.int64(identity.Revision)
}

func (encoder *canonicalEncoder) selector(selector model.EvidencePolicySelector) {
	encoder.string(string(selector.Kind))
	encoder.string(string(selector.Endpoint))
	encoder.string(string(selector.TimeoutProfile))
}

func (encoder *canonicalEncoder) stageBudget(stages model.StageBudgetMS) {
	encoder.int64(stages.Connect)
	encoder.int64(stages.ResponseHeader)
	encoder.int64(stages.FirstByte)
	encoder.int64(stages.FirstEvent)
	encoder.int64(stages.FirstSemantic)
	encoder.int64(stages.Idle)
	encoder.int64(stages.Total)
}

func (encoder *canonicalEncoder) secretRevisions(revisions []model.SecretRevision) {
	canonical := append([]model.SecretRevision(nil), revisions...)
	sort.Slice(canonical, func(left, right int) bool {
		if canonical[left].Name != canonical[right].Name {
			return canonical[left].Name < canonical[right].Name
		}
		if canonical[left].ID != canonical[right].ID {
			return canonical[left].ID < canonical[right].ID
		}
		if canonical[left].Revision != canonical[right].Revision {
			return canonical[left].Revision < canonical[right].Revision
		}
		return !canonical[left].Resolved && canonical[right].Resolved
	})
	encoder.uint32(uint32(len(canonical)))
	for _, revision := range canonical {
		encoder.int64(revision.ID)
		encoder.string(revision.Name)
		encoder.int64(revision.Revision)
		encoder.boolean(revision.Resolved)
	}
}

func (encoder *canonicalEncoder) digest() string {
	sum := sha256.Sum256(encoder.content)
	return "v1:" + hex.EncodeToString(sum[:])
}
