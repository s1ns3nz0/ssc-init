package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func saveFindings(ctx context.Context, tx *sql.Tx, scanID string, findings []model.Finding) error {
	for index, finding := range findings {
		encoded, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("encode finding: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO findings(scan_id,finding_id,finding_index,finding_json) VALUES(?,?,?,?)`, scanID, finding.ID, index, encoded); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
		if finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh {
			seen := formatTime(finding.DetectedAt)
			if _, err = tx.ExecContext(ctx, `INSERT INTO incidents(finding_id,severity,finding_json,first_seen_at,last_seen_at) VALUES(?,?,?,?,?)
ON CONFLICT(finding_id) DO UPDATE SET severity=excluded.severity,finding_json=excluded.finding_json,last_seen_at=max(incidents.last_seen_at,excluded.last_seen_at)`, finding.ID, finding.Severity, encoded, seen, seen); err != nil {
				return fmt.Errorf("record incident: %w", err)
			}
		}
	}
	return nil
}

func loadFindings(ctx context.Context, db *sql.DB, scanID string) ([]model.Finding, error) {
	rows, err := db.QueryContext(ctx, `SELECT finding_id,finding_index,finding_json FROM findings WHERE scan_id=? ORDER BY finding_index`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	var result []model.Finding
	for rows.Next() {
		var id string
		var index int
		var encoded []byte
		if err := rows.Scan(&id, &index, &encoded); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		if index != len(result) {
			return nil, fmt.Errorf("validate findings: non-contiguous index")
		}
		var finding model.Finding
		if err := decodeJSON(encoded, &finding); err != nil || finding.ID != id || !finding.Valid() {
			return nil, fmt.Errorf("validate finding")
		}
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return result, nil
}

// Incidents returns independently retained critical/high finding metadata.
func (s *Store) Incidents(ctx context.Context) ([]model.Finding, error) {
	db, _, release, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := db.QueryContext(ctx, `SELECT finding_json FROM incidents ORDER BY first_seen_at,finding_id`)
	if err != nil {
		return nil, fmt.Errorf("query incidents: %w", err)
	}
	defer rows.Close()
	var result []model.Finding
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		var finding model.Finding
		if err := decodeJSON(encoded, &finding); err != nil || !finding.Valid() || finding.Severity != model.SeverityCritical && finding.Severity != model.SeverityHigh {
			return nil, fmt.Errorf("validate incident")
		}
		result = append(result, finding)
	}
	return result, rows.Err()
}
