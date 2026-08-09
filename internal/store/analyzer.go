package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func saveAnalyzer(ctx context.Context, tx *sql.Tx, scanID string, facts []model.AnalyzerFact, coverage *model.AnalyzerCoverage) error {
	for index, fact := range facts {
		encoded, err := json.Marshal(fact)
		if err != nil {
			return fmt.Errorf("encode analyzer fact: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO analyzer_facts(scan_id,fact_id,fact_index,fact_json) VALUES(?,?,?,?)`, scanID, fact.ID, index, encoded); err != nil {
			return fmt.Errorf("insert analyzer fact: %w", err)
		}
	}
	if coverage != nil {
		encoded, err := json.Marshal(coverage)
		if err != nil {
			return fmt.Errorf("encode analyzer coverage: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO analyzer_coverage(scan_id,coverage_json) VALUES(?,?)`, scanID, encoded); err != nil {
			return fmt.Errorf("insert analyzer coverage: %w", err)
		}
	}
	return nil
}

func loadAnalyzer(ctx context.Context, db *sql.DB, scanID string) ([]model.AnalyzerFact, *model.AnalyzerCoverage, error) {
	rows, err := db.QueryContext(ctx, `SELECT fact_id,fact_index,fact_json FROM analyzer_facts WHERE scan_id=? ORDER BY fact_index`, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("query analyzer facts: %w", err)
	}
	facts := []model.AnalyzerFact{}
	for rows.Next() {
		var id string
		var index int
		var encoded []byte
		if err := rows.Scan(&id, &index, &encoded); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan analyzer fact: %w", err)
		}
		var fact model.AnalyzerFact
		if index != len(facts) || decodeJSON(encoded, &fact) != nil || fact.ID != id || !fact.Valid() {
			rows.Close()
			return nil, nil, fmt.Errorf("validate analyzer fact")
		}
		facts = append(facts, fact)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	var encoded []byte
	err = db.QueryRowContext(ctx, `SELECT coverage_json FROM analyzer_coverage WHERE scan_id=?`, scanID).Scan(&encoded)
	if err == sql.ErrNoRows {
		return facts, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load analyzer coverage: %w", err)
	}
	var coverage model.AnalyzerCoverage
	if decodeJSON(encoded, &coverage) != nil || !coverage.Valid() {
		return nil, nil, fmt.Errorf("validate analyzer coverage")
	}
	return facts, &coverage, nil
}
