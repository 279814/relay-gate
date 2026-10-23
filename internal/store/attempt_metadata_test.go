package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestAttemptMetadataRoundTripAndLegacyUnknown(t *testing.T) {
	st := testStore(t)
	var row model.RequestLog
	if err := json.Unmarshal([]byte(`{"req_id":"new","attempt":1,"attempts":2,"metadata":{"version":1,"execution_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config_generation":4,"settings_revision":8,"endpoint_id":9,"endpoint_revision":3,"auth_profile_revision":7,"route_revision":6,"model_revision":5,"transform_version_id":22,"response_header_at_ms":10,"first_event_at_ms":12,"first_semantic_at_ms":13,"retry_policy":"balanced","request_write_state":"written","capability_effect":"pending","error_class":"unknown","request_diff_reason":"sample_disabled"}}`), &row); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRequestLog(&row); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRequestLog(&model.RequestLog{ReqID: "legacy"}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListRequestLogs(RequestLogFilter{ReqID: "new"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	raw, _ := json.Marshal(rows[0])
	for _, want := range []string{`"config_generation":4`, `"transform_version_id":22`, `"execution_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"request_write_state":"written"`, `"capability_effect":"pending"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s from %s", want, raw)
		}
	}
	rows, err = st.ListRequestLogs(RequestLogFilter{ReqID: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(rows[0])
	if !strings.Contains(string(raw), `"error_class":"unknown"`) || !strings.Contains(string(raw), `"capability_effect":"unknown"`) {
		t.Fatalf("legacy facts invented/omitted: %s", raw)
	}
}

func TestAttemptMetadataIsTypedAndAtomic(t *testing.T) {
	st := testStore(t)
	var row model.RequestLog
	if err := json.Unmarshal([]byte(`{"req_id":"tainted","metadata":{"version":1,"retry_policy":"secret-body"}}`), &row); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRequestLog(&row); err == nil {
		t.Fatal("accepted arbitrary retry policy")
	}
	var count int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM request_log WHERE req_id='tainted'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial metadata insert count=%d err=%v", count, err)
	}
}

func TestSampleListReadsMetadataWithoutLoadingCorruptBodies(t *testing.T) {
	st := testStore(t)
	var smp model.Sample
	if err := json.Unmarshal([]byte(`{"req_id":"sample-meta","attempts":[{"route_id":8,"metadata":{"version":1,"execution_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","transform_version_id":19,"synthetic_completion":true,"retry_policy":"safe","request_write_state":"written","capability_effect":"pending","error_class":"unknown","request_diff_reason":"recorded"}}]}`), &smp); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSample(&smp); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE sample_request SET in_body='v2:broken'; UPDATE sample_attempt SET out_body='v2:broken',resp_body='v2:broken'`); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListSamples(SampleFilter{ReqID: "sample-meta"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("metadata loaded cipherbody: %v %v", rows, err)
	}
	raw, _ := json.Marshal(rows[0])
	if !strings.Contains(string(raw), `"transform_version_id":19`) || !strings.Contains(string(raw), `"synthetic_completion":true`) {
		t.Fatalf("missing sample metadata: %s", raw)
	}
}

func TestAttemptMetadataPairsBothWriterOrdersAndPreservesCommittedFacts(t *testing.T) {
	for _, observationFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "log first", true: "observation first"}[observationFirst], func(t *testing.T) {
			st := testStore(t)
			up := mkUpstream(t, st, "pair")
			id := strings.Repeat("c", 32)
			execution := model.ProbeExecution{ID: id, Trigger: model.TriggerRealTraffic, UpstreamID: up.ID, Endpoint: model.EndpointMessages,
				RecipeBindingUse: model.BindingRealTrafficContext, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic, TemplateID: "builtin:messages", RecipeIdentityRevision: 1,
				ObservationOrder: 1, RealRequestShapeUnavailableReason: model.ShapeUnsupported, ErrorClass: model.ErrorRateLimited, CapabilityDisposition: model.ApplyConfigStale, ResponseHeaderAtMS: 10, FirstEventAtMS: 12, FirstSemanticAtMS: 13}
			row := &model.RequestLog{ReqID: "pair", Metadata: model.AttemptMetadata{Version: 1, ExecutionID: id, CapabilityEffect: "pending"}}
			writeObservation := func() {
				if err := st.InsertProbeExecution(context.Background(), &execution); err != nil {
					t.Fatal(err)
				}
			}
			if observationFirst {
				writeObservation()
			}
			if err := st.InsertRequestLog(row); err != nil {
				t.Fatal(err)
			}
			if !observationFirst {
				writeObservation()
			}
			rows, err := st.ListRequestLogs(RequestLogFilter{ReqID: "pair"})
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows=%v err=%v", rows, err)
			}
			m := rows[0].Metadata
			if !m.ExecutionStored || m.CapabilityEffect != "config_stale" || m.ErrorClass != model.ErrorRateLimited || m.FirstSemanticAtMS != 13 {
				t.Fatalf("did not pair exact execution: %+v", m)
			}
			if _, err := st.db.Exec(`DELETE FROM probe_execution WHERE id=?`, id); err != nil {
				t.Fatal(err)
			}
			rows, err = st.ListRequestLogs(RequestLogFilter{ReqID: "pair"})
			if err != nil {
				t.Fatal(err)
			}
			if m := rows[0].Metadata; m.CapabilityEffect != "config_stale" || m.ErrorClass != model.ErrorRateLimited || m.ExecutionStored {
				t.Fatalf("retention lost committed facts or invented link: %+v", m)
			}
		})
	}
}
