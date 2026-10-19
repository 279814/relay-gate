package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestLiveTransformPublishActivatesItsHealthCounterBeforeSuccess(t *testing.T) {
	s, h, source, publisher := newLivecfgServer(t)
	seedConfig(t, s, 1, 1)
	registry := transform.NewRegistry(8).WithPersist(s.st)
	s.WithTransformRegistry(registry)
	set, err := registry.CreateSet("publish-health")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Test", Value: "1"}}, transform.FailClosed, transform.FailOpen, ""); err != nil {
		t.Fatal(err)
	}
	before, err := source.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	initial := before.Probe.Routes[1].CapabilityRevision
	url := fmt.Sprintf("/admin/api/transforms/%d/publish", set.ID)
	response := do(t, h, "POST", url, `{"route_id":1,"endpoint_id":1}`, true)
	if response.Code != 200 {
		t.Fatalf("publish=%d %s", response.Code, response.Body.String())
	}
	current, err := source.CachedProbeSnapshot()
	if err != nil || current.Routes[1].CapabilityRevision != initial+1 {
		t.Fatalf("successful publish kept stale Route identity: %+v %v", current, err)
	}
	inv, ref := publisher.counts()
	response = do(t, h, "POST", fmt.Sprintf("/admin/api/transforms/%d/shadow", set.ID), `{"route_id":1,"endpoint_id":1}`, true)
	afterInv, afterRef := publisher.counts()
	if response.Code != 200 || inv != afterInv || ref != afterRef {
		t.Fatal("shadow-only change invalidated live health configuration")
	}
	publisher.refreshErr = errors.New("private refresh error")
	publisher.skipInnerRefresh = true
	response = do(t, h, "POST", url, `{"route_id":1,"endpoint_id":1}`, true)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"persisted":true`) || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("committed activation failure=%d %s", response.Code, response.Body.String())
	}
	if _, err := source.CachedProbeSnapshot(); err == nil {
		t.Fatal("failed activation left Probe cache ready")
	}
	row, err := s.st.GetRoute(1)
	if err != nil || row.CapabilityRevision != initial+2 {
		t.Fatalf("pending save lost counter commit: %+v %v", row, err)
	}
}
