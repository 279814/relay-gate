package store

import (
	"reflect"
	"testing"
)

// P0-17 ends the temporary non-page and versionless management adapters.
// Effective fixture callers must use the same bounded/CAS domain as production.
func TestStoreManagementAdaptersHaveRetired(t *testing.T) {
	storeType := reflect.TypeOf((*Store)(nil))
	for _, name := range []string{
		"ListUpstreams", "ListModelNames", "ListRoutes",
		"UpdateUpstream", "UpdateModelName", "UpdateRoute",
		"DeleteUpstream", "DeleteModelName", "DeleteRoute",
	} {
		if _, exists := storeType.MethodByName(name); exists {
			t.Errorf("temporary Store.%s adapter still exists", name)
		}
	}
}
