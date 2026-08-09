package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/s1ns3nz0/ssc-init/internal/privacy"
	"github.com/s1ns3nz0/ssc-init/internal/quarantine"
)

var ErrInvalidQuarantineTransition = errors.New("invalid quarantine transition")

func (s *Store) SaveQuarantineRecord(ctx context.Context, record quarantine.Record) error {
	if !record.Valid() {
		return ErrInvalidQuarantineTransition
	}
	encoded, err := json.Marshal(record)
	if err != nil || privacy.ContainsSensitiveValue(string(encoded)) {
		return ErrSensitiveSnapshot
	}
	db, _, release, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin quarantine transaction: %w", err)
	}
	defer tx.Rollback()
	var previousJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT record_json FROM quarantine_records WHERE id=?`, record.ID).Scan(&previousJSON)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("load quarantine record failed")
	}
	if len(previousJSON) > 0 {
		var previous quarantine.Record
		if decodeJSON(previousJSON, &previous) != nil || !validQuarantineTransition(previous.State, record.State) {
			return ErrInvalidQuarantineTransition
		}
	} else if record.State != quarantine.StateRequested {
		return ErrInvalidQuarantineTransition
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO quarantine_records(id,state,record_json) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,record_json=excluded.record_json`, record.ID, record.State, encoded); err != nil {
		return errors.New("save quarantine record failed")
	}
	return tx.Commit()
}

func (s *Store) QuarantineRecords(ctx context.Context) ([]quarantine.Record, error) {
	db, _, release, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := db.QueryContext(ctx, `SELECT id,state,record_json FROM quarantine_records ORDER BY id`)
	if err != nil {
		return nil, errors.New("load quarantine records failed")
	}
	defer rows.Close()
	records := []quarantine.Record{}
	for rows.Next() {
		var id string
		var state quarantine.State
		var encoded []byte
		if rows.Scan(&id, &state, &encoded) != nil {
			return nil, errors.New("load quarantine records failed")
		}
		var record quarantine.Record
		if decodeJSON(encoded, &record) != nil || !record.Valid() || record.ID != id || record.State != state {
			return nil, errors.New("validate quarantine record failed")
		}
		records = append(records, record)
	}
	if rows.Err() != nil {
		return nil, errors.New("load quarantine records failed")
	}
	return records, nil
}

func validQuarantineTransition(previous, next quarantine.State) bool {
	return previous == quarantine.StateRequested && (next == quarantine.StateQuarantined || next == quarantine.StateFailed) ||
		previous == quarantine.StateQuarantined && next == quarantine.StateRestored
}
