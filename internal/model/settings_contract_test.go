package model

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSettingsRuntimeContainsOnlyCurrentStageFields(t *testing.T) {
	raw, err := json.Marshal(DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"real_first_token_sec", "l2_first_token_sec", "count_tokens_sec"} {
		if _, present := fields[key]; present {
			t.Errorf("runtime Settings still exposes legacy field %s", key)
		}
	}
}

func TestSettingsRejectsTimeoutDurationOverflow(t *testing.T) {
	settings := DefaultSettings()
	settings.RealTotalSec = int((time.Duration(1<<63-1) / time.Second) + 1)
	if err := settings.Validate(); !errors.Is(err, ErrValidation) {
		t.Fatalf("duration-overflow timeout accepted: %v", err)
	}
}

func TestSettingsRejectsConnectBudgetBeyondItsScenarioTotal(t *testing.T) {
	for _, scenario := range []string{"real", "L1", "L2"} {
		t.Run(scenario, func(t *testing.T) {
			settings := DefaultSettings()
			switch scenario {
			case "real":
				settings.RealConnectSec = settings.RealTotalSec + 1
			case "L1":
				settings.L1ConnectSec = settings.L1TotalSec + 1
			case "L2":
				settings.L2ConnectSec = settings.L2TotalSec + 1
			}
			if err := settings.Validate(); !errors.Is(err, ErrValidation) {
				t.Fatalf("connect beyond total accepted: %v", err)
			}
		})
	}
}
