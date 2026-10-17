package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func observedProfile(upstreamID int64, family, hash string) *model.ClientProbeProfile {
	return &model.ClientProbeProfile{UpstreamID: upstreamID, Endpoint: model.EndpointMessages, ClientFamily: family, ShapeHash: hash,
		BodyTemplate: []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1}`), SeenCount: 1}
}

func TestObserveClientProfileConcurrentTelemetryPreservesRevision(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "observe-concurrent")
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorsSeen <- st.UpsertClientProbeProfile(context.Background(), observedProfile(up.ID, "generic", "same-shape"))
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: up.ID})
	if err != nil || len(page.Items) != 1 || page.Items[0].SeenCount != 16 || page.Items[0].Revision != 1 {
		t.Fatalf("duplicate observation changed identity: %+v %v", page, err)
	}
	first := page.Items[0]
	markTested(t, st, first, up)
	before, err := loadProfile(t, st, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertClientProbeProfile(context.Background(), observedProfile(up.ID, "generic", "same-shape")); err != nil {
		t.Fatal(err)
	}
	after, err := loadProfile(t, st, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != model.ProfileTested || after.Revision != before.Revision || after.SeenCount != 17 || after.TestedExecutionID != before.TestedExecutionID {
		t.Fatalf("telemetry overwrote tested binding: %+v", after)
	}
}

func TestObserveClientProfileScopeCapacityProtectsHistory(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "observe-capacity")
	var profiles []*model.ClientProbeProfile
	for i := 0; i < 8; i++ {
		p := mkCandidate(t, st, up.ID, "generic", fmt.Sprintf("shape-%d", i))
		profiles = append(profiles, p)
		if _, err := st.DB().Exec(`UPDATE client_probe_profile SET last_seen_at=? WHERE id=?`, i+1, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	execution := profileTestExecution(t, st, profiles[0], up, "protected-profile-history")
	execution.Success = false
	execution.ErrorClass = model.ErrorTransient
	if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
		t.Fatal(err)
	}
	newProfile := observedProfile(up.ID, "generic", "new-shape")
	if err := st.UpsertClientProbeProfile(context.Background(), newProfile); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListClientProfilesPage(context.Background(), model.ClientProfileFilter{UpstreamID: up.ID})
	if err != nil || len(page.Items) != 8 {
		t.Fatalf("scope not bounded: %+v %v", page, err)
	}
	if _, err := loadProfile(t, st, profiles[0].ID); err != nil {
		t.Fatalf("historical profile evicted: %v", err)
	}
	if _, err := loadProfile(t, st, profiles[1].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest eligible profile not evicted: %v", err)
	}
}

func TestObserveClientProfileCapacityRejectsProtectedRows(t *testing.T) {
	for _, limit := range []int{64, 2048} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			st := testStore(t)
			protected := mkUpstream(t, st, "protected-profiles")
			target := protected
			if limit == 2048 {
				target = mkUpstream(t, st, "new-profile-site")
			}
			_, err := st.DB().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
			INSERT INTO client_probe_profile(upstream_id,endpoint,status,safe_headers_json,fixed_raw_query,query_shape_json,body_template,body_shape_json,client_family,shape_hash,revision,last_seen_at,seen_count,created_at,updated_at)
			SELECT ?,'messages','disabled','[]','','{}','{}','{}','historical','protected-'||i,1,1,1,1,1 FROM n`, limit, protected.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.UpsertClientProbeProfile(context.Background(), observedProfile(target.ID, "new-family", "fresh-shape")); !errors.Is(err, ErrClientProfileCapacity) {
				t.Fatalf("protected capacity should reject: %v", err)
			}
			var count int
			if err := st.DB().QueryRow(`SELECT COUNT(*) FROM client_probe_profile`).Scan(&count); err != nil || count != limit {
				t.Fatalf("protected rows changed: %d %v", count, err)
			}
		})
	}
}

func TestObserveClientProfileReplacementFailureRollsBackVictim(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "observe-rollback")
	var ids []int64
	for i := 0; i < 8; i++ {
		ids = append(ids, mkCandidate(t, st, up.ID, "generic", fmt.Sprintf("old-%d", i)).ID)
	}
	profile := observedProfile(up.ID, "generic", "bad-reference")
	profile.SafeHeaders = []model.HeaderTemplate{{Name: "X-Custom", Values: []string{"{{SECRET:missing}}"}}}
	if err := st.UpsertClientProbeProfile(context.Background(), profile); err == nil {
		t.Fatal("missing secret was accepted")
	}
	for _, id := range ids {
		if _, err := loadProfile(t, st, id); err != nil {
			t.Fatalf("failed insert lost victim %d: %v", id, err)
		}
	}
	if err := st.UpsertClientProbeProfile(context.Background(), observedProfile(up.ID, "generic", "valid-after-rollback")); err != nil {
		t.Fatal(err)
	}
}

func TestObserveClientProfileSameHashCannotChangeExecutableShape(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "observe-collision")
	profile := observedProfile(up.ID, "generic", "existing-shape")
	if err := st.UpsertClientProbeProfile(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	changed := observedProfile(up.ID, "generic", "existing-shape")
	changed.BodyTemplate = []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":999}`)
	if err := st.UpsertClientProbeProfile(context.Background(), changed); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("shape identity collision accepted: %v", err)
	}
	unchanged, err := loadProfile(t, st, profile.ID)
	if err != nil || unchanged.SeenCount != 1 || unchanged.Revision != 1 || string(unchanged.BodyTemplate) != `{"model":"{{UPSTREAM_MODEL}}","max_tokens":1}` {
		t.Fatalf("collision mutated candidate: %+v %v", unchanged, err)
	}
}

func TestObserveClientProfileEvictionSkipsRequiredSecretHistory(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "required-secret-history")
	if _, err := st.CreateProbeSecret("profile-history", []byte("fixture-probe-secret")); err != nil {
		t.Fatal(err)
	}
	protected := observedProfile(up.ID, "generic", "protected-required-secret")
	protected.SafeHeaders = []model.HeaderTemplate{{Name: "X-Custom", Values: []string{"{{SECRET:profile-history}}"}}}
	if err := st.CreateClientProfileCandidate(context.Background(), protected); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE client_probe_profile SET last_seen_at=1 WHERE id=?`, protected.ID); err != nil {
		t.Fatal(err)
	}
	var eligibleID int64
	for i := 0; i < 7; i++ {
		profile := mkCandidate(t, st, up.ID, "generic", fmt.Sprintf("eligible-%d", i))
		if i == 0 {
			eligibleID = profile.ID
		}
		if _, err := st.DB().Exec(`UPDATE client_probe_profile SET last_seen_at=? WHERE id=?`, i+2, profile.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertClientProbeProfile(context.Background(), observedProfile(up.ID, "generic", "fresh")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(t, st, protected.ID); err != nil {
		t.Fatalf("required-secret history was removed: %v", err)
	}
	if _, err := loadProfile(t, st, eligibleID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest eligible alternative was not evicted: %v", err)
	}
}

func TestObserveClientProfileRejectsNewShapeWhenLegacyRowsExceedBounds(t *testing.T) {
	for _, count := range []int{9, 65, 2049} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			st := testStore(t)
			up := mkUpstream(t, st, "legacy-over-capacity")
			family := "generic"
			if count != 9 {
				family = "old-family"
			}
			if _, err := st.DB().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?)
				INSERT INTO client_probe_profile(upstream_id,endpoint,status,safe_headers_json,fixed_raw_query,query_shape_json,body_template,body_shape_json,client_family,shape_hash,revision,last_seen_at,seen_count,created_at,updated_at)
				SELECT ?,'messages','candidate','[]','','{}','{}','{}',?,'old-'||i,1,1,1,1,1 FROM n`, count, up.ID, family); err != nil {
				t.Fatal(err)
			}
			target := up
			if count == 2049 {
				target = mkUpstream(t, st, "new-site")
			}
			if err := st.UpsertClientProbeProfile(context.Background(), observedProfile(target.ID, "generic", "fresh")); !errors.Is(err, ErrClientProfileCapacity) {
				t.Fatalf("over-capacity observation should be dropped: %v", err)
			}
			var after int
			if err := st.DB().QueryRow(`SELECT COUNT(*) FROM client_probe_profile`).Scan(&after); err != nil || after != count {
				t.Fatalf("legacy rows changed: %d %v", after, err)
			}
		})
	}
}
