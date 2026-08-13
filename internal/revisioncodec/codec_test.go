package revisioncodec

import (
	"reflect"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

func TestObservationAndSecretRevisionTokensUseStableCanonicalEncoding(t *testing.T) {
	secrets := []model.SecretRevision{
		{ID: 31, Name: "zeta", Revision: 32, Resolved: false},
		{ID: 21, Name: "alpha", Revision: 22, Resolved: true},
	}
	original := append([]model.SecretRevision(nil), secrets...)
	revision := model.SemanticRevision{
		UpstreamNetwork:          11,
		UpstreamCredential:       12,
		EndpointID:               13,
		EndpointRevision:         14,
		ModelCapability:          15,
		RouteCapability:          16,
		AuthProfile:              17,
		RecipeIdentity:           model.RecipeIdentity{Storage: model.RecipeStorageDB, Origin: model.RecipeManual, DBVersionID: 18},
		RecipeBindingRevision:    19,
		ProbeSettingsFingerprint: "settings-v1",
		ProbeSecrets:             secrets,
		RequestTransform:         20,
	}

	if got, want := NewObservationToken(revision), "v1:12d8d16e396f217fac511705350b003ba08ad21e9235581c204de3ecec9322f5"; got != want {
		t.Fatalf("observation token = %q, want golden %q", got, want)
	}
	if got, want := SecretRevisionSetHash(secrets), "v1:ce65ffbdbc5d2ee8a7cb2f32d1e60bea620ad9e03347926f0438e2412c0430f9"; got != want {
		t.Fatalf("secret set hash = %q, want golden %q", got, want)
	}
	if !reflect.DeepEqual(secrets, original) {
		t.Fatalf("codec mutated caller slice: got %+v want %+v", secrets, original)
	}

	reordered := revision
	reordered.ProbeSecrets = []model.SecretRevision{secrets[1], secrets[0]}
	if NewObservationToken(reordered) != NewObservationToken(revision) || SecretRevisionSetHash(reordered.ProbeSecrets) != SecretRevisionSetHash(secrets) {
		t.Fatal("secret input order must not affect canonical tokens")
	}

	mutations := []model.SemanticRevision{revision, revision, revision, revision}
	mutations[0].EndpointID++
	mutations[1].ProbeSecrets = append([]model.SecretRevision(nil), secrets...)
	mutations[1].ProbeSecrets[0].ID++
	mutations[2].ProbeSecrets = append([]model.SecretRevision(nil), secrets...)
	mutations[2].ProbeSecrets[0].Revision++
	mutations[3].ProbeSecrets = append([]model.SecretRevision(nil), secrets...)
	mutations[3].ProbeSecrets[0].Resolved = !mutations[3].ProbeSecrets[0].Resolved
	for index, mutated := range mutations {
		if NewObservationToken(mutated) == NewObservationToken(revision) {
			t.Errorf("semantic mutation %d did not change token", index)
		}
	}
}

func TestEvidencePolicyFingerprintsIncludeOnlyAttemptRelevantSettings(t *testing.T) {
	settings := model.DefaultSettings()
	selector := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
	capability, err := BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	reachability, err := BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := capability.Stages, (model.StageBudgetMS{
		Connect: 30_000, ResponseHeader: 300_000, FirstByte: 300_000,
		FirstEvent: 300_000, FirstSemantic: 300_000, Idle: 120_000, Total: 600_000,
	}); got != want {
		t.Fatalf("capability stages = %+v, want %+v", got, want)
	}
	if reachability.ConnectMS != 30_000 || reachability.ResponseHeaderMS != 300_000 || reachability.TotalMS != 600_000 {
		t.Fatalf("reachability policy = %+v", reachability)
	}

	baseCapability := ProbeSettingsFingerprint(capability)
	baseReachability := ReachabilitySettingsFingerprint(reachability)
	unrelated := settings
	unrelated.GlobalL2Concurrency++
	unrelated.L2IntervalAliveSec++
	unrelated.SampleKeepCount++
	unrelated.RetryMaxAttempts = 1
	unrelatedCapability, _ := BuildCapabilityEvidencePolicy(unrelated, selector)
	unrelatedReachability, _ := BuildReachabilityEvidencePolicy(unrelated, selector)
	if ProbeSettingsFingerprint(unrelatedCapability) != baseCapability || ReachabilitySettingsFingerprint(unrelatedReachability) != baseReachability {
		t.Fatal("scheduling/sample/retry settings must not invalidate evidence")
	}

	thresholdChanged := settings
	thresholdChanged.FailThreshold++
	thresholdCapability, _ := BuildCapabilityEvidencePolicy(thresholdChanged, selector)
	thresholdReachability, _ := BuildReachabilityEvidencePolicy(thresholdChanged, selector)
	if ProbeSettingsFingerprint(thresholdCapability) != baseCapability {
		t.Fatal("reachability threshold changed capability fingerprint")
	}
	if ReachabilitySettingsFingerprint(thresholdReachability) == baseReachability {
		t.Fatal("reachability threshold did not change reachability fingerprint")
	}

	ttlChanged := capability
	ttlChanged.State.TransientTTL += time.Second
	if ProbeSettingsFingerprint(ttlChanged) == baseCapability {
		t.Fatal("capability TTL did not change capability fingerprint")
	}
	if ReachabilitySettingsFingerprint(reachability) != baseReachability {
		t.Fatal("capability TTL changed reachability fingerprint")
	}
}

func TestEvidencePolicySelectorRejectsInvalidCombinations(t *testing.T) {
	settings := model.DefaultSettings()
	tests := []model.EvidencePolicySelector{
		{Kind: model.EvidenceL1, Endpoint: model.EndpointMessages},
		{Kind: model.EvidenceL2, Endpoint: model.EndpointModels, TimeoutProfile: model.TimeoutL2Standard},
		{Kind: model.EvidenceL2, Endpoint: model.EndpointMessages},
		{Kind: model.EvidenceCountTokens, Endpoint: model.EndpointMessages},
		{Kind: model.EvidenceRealTraffic, Endpoint: model.EndpointModels},
	}
	for _, selector := range tests {
		if _, err := BuildCapabilityEvidencePolicy(settings, selector); err == nil {
			t.Errorf("invalid selector %+v accepted", selector)
		}
	}

	settings.L2FirstSemanticSec = 299
	longThink := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2LongThink,
	}
	if _, err := BuildCapabilityEvidencePolicy(settings, longThink); err == nil {
		t.Fatal("long-thinking policy below 300 seconds accepted")
	}
	standard := longThink
	standard.TimeoutProfile = model.TimeoutL2Standard
	if _, err := BuildCapabilityEvidencePolicy(settings, standard); err != nil {
		t.Fatalf("standard policy may use a shorter semantic budget: %v", err)
	}
}

func TestReachabilityTokenGoldenVector(t *testing.T) {
	revision := model.ReachabilityRevision{NetworkRevision: 41, SettingsFingerprint: "reach-settings-v1"}
	if got, want := NewReachabilityToken(revision), "v1:31bc6eb603ed61dc52283c51b05d523f8859cec7f46625fa6ecea56f69741d73"; got != want {
		t.Fatalf("reachability token = %q, want golden %q", got, want)
	}
	changedNetwork := revision
	changedNetwork.NetworkRevision++
	changedSettings := revision
	changedSettings.SettingsFingerprint += "-changed"
	if NewReachabilityToken(changedNetwork) == NewReachabilityToken(revision) || NewReachabilityToken(changedSettings) == NewReachabilityToken(revision) {
		t.Fatal("network and settings revisions must both affect reachability token")
	}
}
