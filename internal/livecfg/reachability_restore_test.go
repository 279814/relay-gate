package livecfg

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

func TestDurableNegativeReachabilityRestoresOnlyVerifiedCurrentIncarnation(t *testing.T) {
	ctx := context.Background()
	cipher, err := store.NewCipher("test-encryption-key-32-bytes-long")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "negative.db")
	st, err := store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	up := &model.Upstream{Name: "durable-negative", BaseURL: "https://example.test", APIKey: "fixture-negative-private-key", Enabled: true}
	if err := st.CreateUpstream(up); err != nil {
		t.Fatal(err)
	}
	source, _ := newSource(t, st)
	if _, err := source.Bundle(); err != nil {
		t.Fatal(err)
	}
	snap, err := source.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	exp, err := snap.ReachabilityExpectation(up.ID, selector)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(snap.Settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	// Strictly later than creation: an equal millisecond cannot establish which
	// incarnation a corrupt imported row belongs to and is deliberately rejected.
	at := time.UnixMilli(up.CreatedAt + 10)
	reducer := health.NewObservationReducer(func() time.Time { return at })
	ep := snap.Endpoints[up.ID][model.EndpointModels]
	for order := int64(1); order <= int64(policy.State.UnreachableThreshold); order++ {
		exec := model.ProbeExecution{ID: "restore-negative-" + string(rune('0'+order)), EvidenceHash: "negative", UpstreamID: up.ID,
			EndpointID: ep.ID, EndpointRevision: ep.Revision, AuthProfileRevision: ep.AuthProfile.Revision,
			RecipeBindingUse: model.BindingResolved, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic, TemplateID: "builtin:models", RecipeIdentityRevision: 1, Final: true, Scope: model.ScopeUpstreamReachability,
			Endpoint: model.EndpointModels, Trigger: model.TriggerScheduled, SentAtMS: at.UnixMilli(), DoneAtMS: at.Add(time.Millisecond).UnixMilli(),
			ObservationOrder: order, ErrorClass: model.ErrorUnreachable, Capability: model.CapabilityUnknown,
			UpstreamNetworkRevision: exp.Revision.NetworkRevision, ReachabilityPolicySelector: selector,
			ReachabilitySettingsFingerprint: exp.Revision.SettingsFingerprint, ReachabilityToken: exp.ObservationToken}
		if _, err := st.CommitProbeObservation(ctx, &model.ProbeObservation{Execution: exec, ReachabilityExpectation: &exp, ReachabilityPolicy: &policy.State}, reducer); err != nil {
			t.Fatal(err)
		}
	}
	// Normal deletion is prohibited while this durable history exists.
	if err := st.DeleteUpstreamWithRevision(ctx, up.ID, up.Revision); err == nil {
		t.Fatal("negative history allowed deleting its identity")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	restore := func(want model.ReachabilityState) {
		t.Helper()
		freshSource, _ := newSource(t, st)
		if _, err := freshSource.Bundle(); err != nil {
			t.Fatal(err)
		}
		fresh := health.NewReachabilityTracker(freshSource)
		if _, err := fresh.RestoreNegatives(ctx, st); err != nil {
			t.Fatal(err)
		}
		current, err := st.GetUpstream(up.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got := fresh.Effective(up.ID, current.NetworkRevision); got != want {
			t.Fatalf("cold tracker=%s want %s", got, want)
		}
	}
	restore(model.ReachabilityUnreachable)
	if _, err := st.DB().Exec(`UPDATE upstream_reachability SET state='reachable' WHERE upstream_id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	restore(model.ReachabilityUnknown)
	if _, err := st.DB().Exec(`UPDATE upstream_reachability SET state='unreachable' WHERE upstream_id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	// Model the janitor's execution removal explicitly. Retention scheduling is
	// independently tested; recovery must not require retained audit executions.
	if _, err := st.DB().Exec(`DELETE FROM probe_execution`); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM probe_execution`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("janitor remaining=%d err=%v", remaining, err)
	}
	restore(model.ReachabilityUnreachable)
	// Old network and settings evidence must not be revived by cold startup.
	if _, err := st.DB().Exec(`UPDATE upstream SET network_revision=network_revision+1 WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	restore(model.ReachabilityUnknown)
	if _, err := st.DB().Exec(`UPDATE upstream SET network_revision=network_revision-1 WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	settings, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.FailThreshold++
	if err := st.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	restore(model.ReachabilityUnknown)
	settings.FailThreshold--
	if err := st.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	// Simulate damaged/imported reused numeric IDs with reset revisions. The
	// durable negative predates (or ties) the current identity, so do not stamp it.
	for _, created := range []int64{at.UnixMilli(), at.Add(time.Millisecond).UnixMilli()} {
		if _, err := st.DB().Exec(`UPDATE upstream SET created_at=? WHERE id=?`, created, up.ID); err != nil {
			t.Fatal(err)
		}
		restore(model.ReachabilityUnknown)
	}
	if _, err := st.DB().Exec(`UPDATE upstream_reachability SET last_error_at=0 WHERE upstream_id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	restore(model.ReachabilityUnknown)
	// Simulate an orphan imported with FK checks disabled. A timestamp/token
	// cannot associate it with any current upstream; the join must exclude it.
	conn, err := st.DB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`)
	if _, err := conn.ExecContext(ctx, `INSERT INTO upstream_reachability
		(upstream_id,evidence_kind,endpoint,timeout_profile,state,consecutive_ok,consecutive_fail,
		last_ok_at,last_error_at,last_error,last_connect_ms,last_tls_ms,last_header_ms,
		observed_network_revision,settings_fingerprint,observation_token,last_observation_order)
		SELECT 99999,evidence_kind,endpoint,timeout_profile,state,consecutive_ok,consecutive_fail,
		last_ok_at,last_error_at,last_error,last_connect_ms,last_tls_ms,last_header_ms,
		observed_network_revision,settings_fingerprint,observation_token,last_observation_order
		FROM upstream_reachability WHERE upstream_id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	rows, err := st.LoadCurrentNegativeReachability(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.UpstreamID == 99999 {
			t.Fatal("orphan was assigned a current identity")
		}
	}
}
