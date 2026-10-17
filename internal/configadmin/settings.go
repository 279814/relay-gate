package configadmin

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

type SettingsStore interface {
	GetSettingsWithRevision() (model.Settings, int64, error)
	SaveSettingsWithRevision(model.Settings, int64) (int64, error)
}

// SettingsService owns validation and the exact client revision CAS. HTTP
// orchestrates the existing ConfigPublisher only after this commit succeeds.
type SettingsService struct{ store SettingsStore }

func NewSettings(store SettingsStore) *SettingsService { return &SettingsService{store: store} }

func (s *SettingsService) GetSettings(_ context.Context) (model.Settings, int64, error) {
	return s.store.GetSettingsWithRevision()
}

func (s *SettingsService) UpdateSettings(_ context.Context, in model.Settings, expectedRevision int64) (model.Settings, int64, error) {
	if expectedRevision < 1 {
		return model.Settings{}, 0, model.WrapValidation("expected_revision 必须是正整数，请先读取设置")
	}
	if err := in.Validate(); err != nil {
		return model.Settings{}, 0, err
	}
	revision, err := s.store.SaveSettingsWithRevision(in, expectedRevision)
	return in, revision, err
}
