package outbound

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probetemplate"
)

type countedBoundSecrets struct {
	value probetemplate.ResolvedSecret
	err   error
	calls atomic.Int32
}

func (s *countedBoundSecrets) ResolveProbeSecret(context.Context, string) (probetemplate.ResolvedSecret, error) {
	s.calls.Add(1)
	return s.value, s.err
}

func TestValuesBindingsRejectOldOrUnknownSecretIdentity(t *testing.T) {
	for _, change := range []string{"revision", "recreated", "missing-binding", "unresolved-binding"} {
		t.Run(change, func(t *testing.T) {
			source := &countedBoundSecrets{value: probetemplate.ResolvedSecret{ID: 11, Revision: 2, Plain: []byte("temporary-bound-secret")}}
			binding := []model.SecretRevision{{ID: 11, Name: "bound-auth", Revision: 2, Resolved: true}}
			switch change {
			case "revision":
				source.value.Revision++
			case "recreated":
				source.value.ID++
			case "missing-binding":
				binding = nil
			case "unresolved-binding":
				binding[0].Resolved = false
			}
			values := (Values{Secrets: source}).WithBindings(binding)
			if _, err := values.ResolveValue(context.Background(), "SECRET:bound-auth"); !errors.Is(err, ErrURLConfig) || errors.Is(err, ErrSecretSourceRead) {
				t.Fatalf("stale/missing binding must be configuration failure: %v", err)
			}
			if (change == "missing-binding" || change == "unresolved-binding") && source.calls.Load() != 0 {
				t.Error("unbound credential consulted the current source by name")
			}
		})
	}
}

func TestValuesBindingsPreserveSourceReadErrorClassWithoutCredentialText(t *testing.T) {
	const private = "temporary-source-error-private-marker"
	source := &countedBoundSecrets{err: errors.New(private)}
	values := (Values{Secrets: source}).WithBindings([]model.SecretRevision{{ID: 11, Name: "bound-auth", Revision: 2, Resolved: true}})
	_, err := values.ResolveValue(context.Background(), "SECRET:bound-auth")
	if !errors.Is(err, ErrSecretSourceRead) || errors.Is(err, ErrURLConfig) || errors.Is(err, ErrAuthConfig) || strings.Contains(err.Error(), private) {
		t.Fatalf("source error lost its class or exposed driver material: %v", err)
	}
}

func TestValuesBindingsRequireRedactableSecretAtTwelveByteBoundary(t *testing.T) {
	for _, length := range []int{model.MinRedactableKeyLen - 1, model.MinRedactableKeyLen} {
		plain := strings.Repeat("x", length)
		source := &countedBoundSecrets{value: probetemplate.ResolvedSecret{ID: 11, Revision: 2, Plain: []byte(plain)}}
		values := (Values{Secrets: source}).WithBindings([]model.SecretRevision{{ID: 11, Name: "bound-auth", Revision: 2, Resolved: true}})
		value, err := values.ResolveValue(context.Background(), "SECRET:bound-auth")
		if length < model.MinRedactableKeyLen {
			if !errors.Is(err, ErrURLConfig) || errors.Is(err, ErrSecretSourceRead) || len(value.Plain) != 0 {
				t.Error("unredactable credential did not fail closed before rendering")
			}
		} else if err != nil || string(value.Plain) != plain {
			t.Error("credential at the exact redaction boundary was rejected")
		}
	}
}

func TestResolvedTargetSharesOneCredentialReadAcrossQueryAndAuth(t *testing.T) {
	const private = "temporary-single-source-auth-secret"
	source := &countedBoundSecrets{value: probetemplate.ResolvedSecret{ID: 11, Revision: 2, Plain: []byte(private)}}
	endpoint := canonicalEndpoint(model.EndpointMessages)
	endpoint.FixedQueryTemplate = "site_token={{SECRET:bound-auth}}"
	endpoint.AuthProfile = model.EndpointAuthProfile{Mode: model.AuthModeManualHeaders, SecretRef: "probe:bound-auth", Revision: 1, ManualHeaders: []model.HeaderTemplate{{Name: "X-Bound-Key", Values: []string{"prefix {{SECRET:bound-auth}}", "{{SECRET:bound-auth}}"}}}}
	endpoint.BoundSecrets = []model.SecretRevision{{ID: 11, Name: "bound-auth", Revision: 2, Resolved: true}}
	provider := newTestProvider(&fakeEndpoints{byKind: map[model.EndpointKind]*model.UpstreamEndpoint{model.EndpointMessages: endpoint}}, nil)
	target, err := provider.ResolveTarget(context.Background(), TargetInput{Upstream: testUpstream(), Endpoint: model.EndpointMessages, Values: Values{Secrets: source}, Use: ResolveRealForward})
	if err != nil {
		t.Fatal(err)
	}
	if target.CredentialValues == nil {
		t.Fatal("production Resolver returned no credential trace")
	}
	header := http.Header{}
	if err := ApplyAuth(context.Background(), header, AuthInput{Profile: target.AuthProfile, Values: target.CredentialValues}); err != nil {
		t.Fatal(err)
	}
	if source.calls.Load() != 1 {
		t.Fatalf("query/manual auth reread source %d times", source.calls.Load())
	}
	if !reflect.DeepEqual(target.ResolvedSecrets(), []string{private}) {
		t.Error("credential trace lost the original value or duplicated it")
	}
	if source.calls.Load() != 1 {
		t.Error("reading the redaction list consulted SecretSource again")
	}
	copy := target.ResolvedSecrets()
	copy[0] = "mutated"
	if !reflect.DeepEqual(target.ResolvedSecrets(), []string{private}) {
		t.Error("caller mutated the credential trace through its redaction list")
	}
}

type blockingBoundSecrets struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (source *blockingBoundSecrets) ResolveProbeSecret(ctx context.Context, _ string) (probetemplate.ResolvedSecret, error) {
	source.calls.Add(1)
	select {
	case source.started <- struct{}{}:
	default:
	}
	select {
	case <-source.release:
		return probetemplate.ResolvedSecret{ID: 11, Revision: 2, Plain: []byte("temporary-concurrent-bound-secret")}, nil
	case <-ctx.Done():
		return probetemplate.ResolvedSecret{}, ctx.Err()
	}
}

func TestCredentialTraceWaitIsBoundedAndDoesNotHoldMetadataLockAcrossSourceRead(t *testing.T) {
	source := &blockingBoundSecrets{started: make(chan struct{}, 1), release: make(chan struct{})}
	values := (Values{Secrets: source}).WithBindings([]model.SecretRevision{{ID: 11, Name: "bound-auth", Revision: 2, Resolved: true}})
	trace := newCredentialValueTrace(values)
	first := make(chan error, 1)
	go func() { _, err := trace.ResolveValue(context.Background(), "SECRET:bound-auth"); first <- err }()
	defer func() {
		close(source.release)
		select {
		case err := <-first:
			if err != nil {
				t.Errorf("original credential read did not finish: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("original credential read remained blocked after release")
		}
	}()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("source read did not start")
	}
	// A second consumer can cancel while the original source read is pending.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := trace.ResolveValue(ctx, "SECRET:bound-auth"); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrSecretSourceRead) {
		t.Fatalf("credential wait ignored its cancellation or lost the read error class: %v", err)
	}
	if source.calls.Load() != 1 {
		t.Error("concurrent consumers duplicated the credential source read")
	}
	listed := make(chan []string, 1)
	go func() { listed <- trace.resolvedSecrets() }()
	select {
	case values := <-listed:
		if len(values) != 0 {
			t.Error("pending source read was reported as a resolved credential")
		}
	case <-time.After(time.Second):
		t.Fatal("redaction metadata waited on a lock held across source I/O")
	}
}
