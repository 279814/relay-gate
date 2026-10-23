package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/279814/relay-gate/internal/model"
)

// GetSampleMetadata never selects a cipher BLOB or a header/URL value.
func (s *Store) GetSampleMetadata(ctx context.Context, id int64) (*model.SampleMetadata, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	value := &model.SampleMetadata{Attempts: []model.SampleAttemptMetadata{}}
	err = tx.QueryRowContext(ctx, `SELECT id,req_id,COALESCE(legacy_sample_id,0),endpoint,model_in,ts_recv FROM sample_request WHERE id=?`, id).Scan(&value.ID, &value.ReqID, &value.LegacySampleID, &value.Endpoint, &value.ModelIn, &value.TSRecv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,ts_recv,ts_sent,ts_first_byte,ts_done,route_id,upstream_id,model_name_id,model_out,resp_status,outcome FROM sample_attempt WHERE request_id=? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var a model.SampleAttemptMetadata
		if err := rows.Scan(&a.ID, &a.TSRecv, &a.TSSent, &a.TSFirstByte, &a.TSDone, &a.RouteID, &a.UpstreamID, &a.ModelNameID, &a.ModelOut, &a.RespStatus, &a.Outcome); err != nil {
			rows.Close()
			return nil, err
		}
		a.Metadata = model.UnknownAttemptMetadata()
		ids = append(ids, a.ID)
		value.Attempts = append(value.Attempts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	metadata, err := loadAttemptMetadata(ctx, tx, "sample_attempt_metadata", ids)
	if err != nil {
		return nil, err
	}
	for i := range value.Attempts {
		if m, ok := metadata[value.Attempts[i].ID]; ok {
			value.Attempts[i].Metadata = m
		}
	}
	value.AttemptCount = len(value.Attempts)
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return value, nil
}
