package runstate_test

import (
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/store"
)

func TestRunStateHasOneRuntimeReaderAndNoImplicitStoreWrites(t *testing.T) {
	for _, contract := range []struct {
		owner reflect.Type
		name  string
	}{
		{reflect.TypeOf((*livecfg.Source)(nil)), "RunState"},
		{reflect.TypeOf((*store.Store)(nil)), "GetRunState"},
		{reflect.TypeOf((*store.Store)(nil)), "SetRunState"},
	} {
		if _, found := contract.owner.MethodByName(contract.name); found {
			t.Errorf("legacy %s.%s still exposed", contract.owner, contract.name)
		}
	}
	for _, owner := range []reflect.Type{reflect.TypeOf(livecfg.PublishedConfig{}), reflect.TypeOf(store.ConfigBundle{})} {
		if _, found := owner.FieldByName("RunState"); found {
			t.Errorf("%s still copies independent Controller state", owner)
		}
	}
}
