package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/279814/relay-gate/internal/transform"
)

// SaveTransformSnapshot replaces all transform tables with the registry snapshot.
func (s *Store) SaveTransformSnapshot(sets []transform.Set, bindings []transform.Binding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM transform_binding`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM transform_version`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM transform_set`); err != nil {
		return err
	}
	for _, set := range sets {
		draftJSON := ""
		if set.Draft != nil {
			b, err := json.Marshal(set.Draft)
			if err != nil {
				return err
			}
			draftJSON = string(b)
		}
		if _, err := tx.Exec(`INSERT INTO transform_set (id, name, created_at, draft_json) VALUES (?,?,?,?)`,
			set.ID, set.Name, set.CreatedAt.UnixMilli(), draftJSON); err != nil {
			return err
		}
		for _, ver := range set.History {
			rules, err := json.Marshal(ver.Rules)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO transform_version
				(id, set_id, revision, created_at, rules_json, req_fail_policy, res_fail_policy, note)
				VALUES (?,?,?,?,?,?,?,?)`,
				ver.ID, set.ID, ver.Revision, ver.CreatedAt.UnixMilli(), string(rules),
				ver.ReqFailPolicy, ver.ResFailPolicy, ver.Note); err != nil {
				return err
			}
		}
	}
	for _, b := range bindings {
		if _, err := tx.Exec(`INSERT INTO transform_binding
			(route_id, endpoint_id, set_id, published_id, shadow_id, revision) VALUES (?,?,?,?,?,?)`,
			b.RouteID, b.EndpointID, b.SetID, b.PublishedID, b.ShadowID, b.Revision); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadTransformSnapshot reads all transform sets/versions/bindings.
func (s *Store) LoadTransformSnapshot() ([]transform.Set, []transform.Binding, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at, draft_json FROM transform_set ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var sets []transform.Set
	setIndex := map[int64]int{}
	for rows.Next() {
		var set transform.Set
		var created int64
		var draftJSON string
		if err := rows.Scan(&set.ID, &set.Name, &created, &draftJSON); err != nil {
			return nil, nil, err
		}
		set.CreatedAt = time.UnixMilli(created).UTC()
		if draftJSON != "" {
			var d transform.Version
			if err := json.Unmarshal([]byte(draftJSON), &d); err != nil {
				return nil, nil, fmt.Errorf("draft json set %d: %w", set.ID, err)
			}
			set.Draft = &d
		}
		setIndex[set.ID] = len(sets)
		sets = append(sets, set)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	vrows, err := s.db.Query(`SELECT id, set_id, revision, created_at, rules_json, req_fail_policy, res_fail_policy, note
		FROM transform_version ORDER BY set_id, id`)
	if err != nil {
		return nil, nil, err
	}
	defer vrows.Close()
	for vrows.Next() {
		var ver transform.Version
		var created int64
		var rulesJSON string
		if err := vrows.Scan(&ver.ID, &ver.SetID, &ver.Revision, &created, &rulesJSON,
			&ver.ReqFailPolicy, &ver.ResFailPolicy, &ver.Note); err != nil {
			return nil, nil, err
		}
		ver.CreatedAt = time.UnixMilli(created).UTC()
		if rulesJSON != "" {
			if err := json.Unmarshal([]byte(rulesJSON), &ver.Rules); err != nil {
				return nil, nil, err
			}
		}
		idx, ok := setIndex[ver.SetID]
		if !ok {
			continue
		}
		sets[idx].History = append(sets[idx].History, ver)
	}
	if err := vrows.Err(); err != nil {
		return nil, nil, err
	}

	brows, err := s.db.Query(`SELECT route_id, endpoint_id, set_id, published_id, shadow_id, revision FROM transform_binding`)
	if err != nil {
		return nil, nil, err
	}
	defer brows.Close()
	var bindings []transform.Binding
	for brows.Next() {
		var b transform.Binding
		if err := brows.Scan(&b.RouteID, &b.EndpointID, &b.SetID, &b.PublishedID, &b.ShadowID, &b.Revision); err != nil {
			return nil, nil, err
		}
		bindings = append(bindings, b)
	}
	return sets, bindings, brows.Err()
}
