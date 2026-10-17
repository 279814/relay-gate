package store

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
)

// DiagnosticRedactionKeys is the complete current key set needed to redact
// administrative diagnostics, including disabled sites without routes. It is
// not an entity list: only encrypted credential columns are read, with no
// configuration parsing, defaults or pagination that could omit a secret.
// Any unreadable key rejects the entire result; callers must omit raw details.
func (s *Store) DiagnosticRedactionKeys(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT api_key_enc FROM upstream WHERE api_key_enc<>''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		key, err := s.cipher.Decrypt(encoded)
		if err != nil {
			return nil, err
		}
		if key != "" {
			if len(key) < model.MinRedactableKeyLen {
				return nil, model.WrapValidation("历史上游凭据过短，诊断无法安全脱敏，请先替换凭据")
			}
			keys = append(keys, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}
