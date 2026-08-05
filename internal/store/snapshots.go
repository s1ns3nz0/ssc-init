package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

// SaveScan atomically persists a scan and immutable inventory snapshot.
func (s *Store) SaveScan(ctx context.Context, scan model.ScanResult, inventory model.Inventory) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin snapshot transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `INSERT INTO scans(id, schema_version, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`,
		scan.ScanID, scan.SchemaVersion, scan.Status, formatTime(scan.StartedAt), formatTime(scan.FinishedAt)); err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	for index, asset := range inventory.Assets {
		encoded, marshalErr := json.Marshal(asset)
		if marshalErr != nil {
			return fmt.Errorf("encode asset %q: %w", asset.ID, marshalErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO assets(scan_id, asset_id, asset_json) VALUES (?, ?, ?)`, scan.ScanID, asset.ID, encoded); err != nil {
			return fmt.Errorf("insert asset %q: %w", asset.ID, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO asset_state(scan_id, asset_id, asset_index, metadata_nil) VALUES (?, ?, ?, ?)`, scan.ScanID, asset.ID, index, boolInt(asset.Metadata == nil)); err != nil {
			return fmt.Errorf("insert asset state %q: %w", asset.ID, err)
		}
	}
	for index, relationship := range inventory.Relationships {
		if _, err = tx.ExecContext(ctx, `INSERT INTO relationships(scan_id, from_id, kind, to_id) VALUES (?, ?, ?, ?)`,
			scan.ScanID, relationship.From, relationship.Kind, relationship.To); err != nil {
			return fmt.Errorf("insert relationship: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO relationship_state(scan_id, from_id, kind, to_id, relationship_index) VALUES (?, ?, ?, ?, ?)`,
			scan.ScanID, relationship.From, relationship.Kind, relationship.To, index); err != nil {
			return fmt.Errorf("insert relationship state: %w", err)
		}
	}
	for _, result := range scan.Coverage {
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return fmt.Errorf("encode coverage %q: %w", result.Collector, marshalErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO coverage(scan_id, collector, result_json) VALUES (?, ?, ?)`, scan.ScanID, result.Collector, encoded); err != nil {
			return fmt.Errorf("insert coverage %q: %w", result.Collector, err)
		}
	}
	for index, inventoryError := range inventory.Errors {
		encoded, marshalErr := json.Marshal(inventoryError)
		if marshalErr != nil {
			return fmt.Errorf("encode inventory error %d: %w", index, marshalErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO inventory_errors(scan_id, error_index, error_json) VALUES (?, ?, ?)`, scan.ScanID, index, encoded); err != nil {
			return fmt.Errorf("insert inventory error %d: %w", index, err)
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO inventory_state(scan_id, assets_nil, relationships_nil, errors_nil) VALUES (?, ?, ?, ?)`,
		scan.ScanID, boolInt(inventory.Assets == nil), boolInt(inventory.Relationships == nil), boolInt(inventory.Errors == nil)); err != nil {
		return fmt.Errorf("insert inventory state: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit snapshot transaction: %w", err)
	}
	return nil
}

// LatestInventory loads the newest inventory by finished time, breaking ties by scan ID.
func (s *Store) LatestInventory(ctx context.Context) (model.Inventory, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, false, err
	}
	var scanID string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM scans ORDER BY finished_at DESC, id DESC LIMIT 1`).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Inventory{}, false, nil
	}
	if err != nil {
		return model.Inventory{}, false, fmt.Errorf("select latest scan: %w", err)
	}

	var assetsNil, relationshipsNil, errorsNil int
	if err := s.db.QueryRowContext(ctx, `SELECT assets_nil, relationships_nil, errors_nil FROM inventory_state WHERE scan_id = ?`, scanID).
		Scan(&assetsNil, &relationshipsNil, &errorsNil); err != nil {
		return model.Inventory{}, false, fmt.Errorf("load inventory state for scan %q: %w", scanID, err)
	}
	if err := validateBoolInts(assetsNil, relationshipsNil, errorsNil); err != nil {
		return model.Inventory{}, false, fmt.Errorf("validate inventory state for scan %q: %w", scanID, err)
	}

	inventory := model.Inventory{}
	assets, err := s.loadAssets(ctx, scanID)
	if err != nil {
		return model.Inventory{}, false, err
	}
	if assetsNil == 0 {
		inventory.Assets = assets
	} else if len(assets) != 0 {
		return model.Inventory{}, false, fmt.Errorf("validate inventory state for scan %q: assets marked nil but rows exist", scanID)
	}
	relationships, err := s.loadRelationships(ctx, scanID)
	if err != nil {
		return model.Inventory{}, false, err
	}
	if relationshipsNil == 0 {
		inventory.Relationships = relationships
	} else if len(relationships) != 0 {
		return model.Inventory{}, false, fmt.Errorf("validate inventory state for scan %q: relationships marked nil but rows exist", scanID)
	}
	inventoryErrors, err := s.loadInventoryErrors(ctx, scanID)
	if err != nil {
		return model.Inventory{}, false, err
	}
	if errorsNil == 0 {
		inventory.Errors = inventoryErrors
	} else if len(inventoryErrors) != 0 {
		return model.Inventory{}, false, fmt.Errorf("validate inventory state for scan %q: errors marked nil but rows exist", scanID)
	}
	return inventory, true, nil
}

func (s *Store) loadAssets(ctx context.Context, scanID string) ([]model.Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.asset_id, a.asset_json, st.asset_index, st.metadata_nil
FROM assets a LEFT JOIN asset_state st ON st.scan_id = a.scan_id AND st.asset_id = a.asset_id
WHERE a.scan_id = ? ORDER BY st.asset_index`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query assets for scan %q: %w", scanID, err)
	}
	defer rows.Close()
	assets := make([]model.Asset, 0)
	expectedIndex := 0
	for rows.Next() {
		var assetID string
		var encoded []byte
		var index sql.NullInt64
		var metadataNil sql.NullInt64
		if err := rows.Scan(&assetID, &encoded, &index, &metadataNil); err != nil {
			return nil, fmt.Errorf("scan asset for scan %q: %w", scanID, err)
		}
		if !index.Valid || !metadataNil.Valid {
			return nil, fmt.Errorf("validate asset %q for scan %q: missing asset state", assetID, scanID)
		}
		if index.Int64 != int64(expectedIndex) {
			return nil, fmt.Errorf("validate assets for scan %q: got index %d, want %d", scanID, index.Int64, expectedIndex)
		}
		var asset model.Asset
		if err := decodeJSON(encoded, &asset); err != nil {
			return nil, fmt.Errorf("decode asset %q for scan %q: %w", assetID, scanID, err)
		}
		if assetID == "" || asset.ID != assetID {
			return nil, fmt.Errorf("validate asset %q for scan %q: JSON id %q does not match row", assetID, scanID, asset.ID)
		}
		if metadataNil.Int64 != 0 && metadataNil.Int64 != 1 {
			return nil, fmt.Errorf("validate asset %q for scan %q: invalid metadata state %d", assetID, scanID, metadataNil.Int64)
		}
		if metadataNil.Int64 == 1 && asset.Metadata != nil {
			return nil, fmt.Errorf("validate asset %q for scan %q: metadata marked nil but JSON contains metadata", assetID, scanID)
		}
		if metadataNil.Int64 == 0 && asset.Metadata == nil {
			asset.Metadata = map[string]string{}
		}
		assets = append(assets, asset)
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets for scan %q: %w", scanID, err)
	}
	return assets, nil
}

func (s *Store) loadRelationships(ctx context.Context, scanID string) ([]model.Relationship, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.from_id, r.to_id, r.kind, st.relationship_index
FROM relationships r LEFT JOIN relationship_state st
ON st.scan_id = r.scan_id AND st.from_id = r.from_id AND st.kind = r.kind AND st.to_id = r.to_id
WHERE r.scan_id = ? ORDER BY st.relationship_index`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query relationships for scan %q: %w", scanID, err)
	}
	defer rows.Close()
	relationships := make([]model.Relationship, 0)
	expectedIndex := 0
	for rows.Next() {
		var relationship model.Relationship
		var index sql.NullInt64
		if err := rows.Scan(&relationship.From, &relationship.To, &relationship.Kind, &index); err != nil {
			return nil, fmt.Errorf("scan relationship for scan %q: %w", scanID, err)
		}
		if !index.Valid {
			return nil, fmt.Errorf("validate relationship for scan %q: missing relationship state", scanID)
		}
		if index.Int64 != int64(expectedIndex) {
			return nil, fmt.Errorf("validate relationships for scan %q: got index %d, want %d", scanID, index.Int64, expectedIndex)
		}
		if relationship.From == "" || relationship.To == "" || relationship.Kind == "" {
			return nil, fmt.Errorf("validate relationship for scan %q: fields must not be empty", scanID)
		}
		relationships = append(relationships, relationship)
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate relationships for scan %q: %w", scanID, err)
	}
	return relationships, nil
}

func (s *Store) loadInventoryErrors(ctx context.Context, scanID string) ([]model.CoverageError, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT error_index, error_json FROM inventory_errors WHERE scan_id = ? ORDER BY error_index`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query inventory errors for scan %q: %w", scanID, err)
	}
	defer rows.Close()
	errorsOut := make([]model.CoverageError, 0)
	expectedIndex := 0
	for rows.Next() {
		var index int
		var encoded []byte
		if err := rows.Scan(&index, &encoded); err != nil {
			return nil, fmt.Errorf("scan inventory error for scan %q: %w", scanID, err)
		}
		if index != expectedIndex {
			return nil, fmt.Errorf("validate inventory errors for scan %q: got index %d, want %d", scanID, index, expectedIndex)
		}
		var inventoryError model.CoverageError
		if err := decodeJSON(encoded, &inventoryError); err != nil {
			return nil, fmt.Errorf("decode inventory error %d for scan %q: %w", index, scanID, err)
		}
		if inventoryError.Code == "" || inventoryError.Message == "" {
			return nil, fmt.Errorf("validate inventory error %d for scan %q: code and message must not be empty", index, scanID)
		}
		errorsOut = append(errorsOut, inventoryError)
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inventory errors for scan %q: %w", scanID, err)
	}
	return errorsOut, nil
}

func decodeJSON(encoded []byte, target any) error {
	if !json.Valid(encoded) {
		return errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

func validateBoolInts(values ...int) error {
	for _, value := range values {
		if value != 0 && value != 1 {
			return fmt.Errorf("invalid boolean value %d", value)
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formatTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
