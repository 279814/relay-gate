package outbound

import (
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestBudgetConstructionNeverSubstitutesLegacyStageValues(t *testing.T) {
	settings := model.DefaultSettings()
	settings.RealResponseHeaderSec, settings.RealFirstByteSec, settings.RealFirstSemanticSec = 0, 0, 0
	settings.L2ResponseHeaderSec, settings.L2FirstByteSec, settings.L2FirstEventSec, settings.L2FirstSemanticSec = 0, 0, 0, 0
	for name, budget := range map[string]Budget{"real": RealBudget(settings), "L2": L2Budget(settings)} {
		if budget.ResponseHead != 0 || budget.FirstByte != 0 || budget.FirstEvent != 0 || budget.FirstSemantic != 0 {
			t.Errorf("%s silently substituted another timeout: %+v", name, budget)
		}
	}
}
