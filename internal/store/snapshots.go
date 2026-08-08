package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// SaveScan atomically persists a scan and immutable inventory snapshot.
func (s *Store) SaveScan(ctx context.Context, scan model.ScanResult, inventory model.Inventory) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSnapshot(scan, inventory); err != nil {
		return err
	}
	encodedScope, err := json.Marshal(scan.Scope)
	if err != nil {
		return fmt.Errorf("encode scan scope: %w", err)
	}
	db, guard, release, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin snapshot transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `INSERT INTO scans(id, schema_version, status, started_at, finished_at, scope_json) VALUES (?, ?, ?, ?, ?, ?)`,
		scan.ScanID, scan.SchemaVersion, scan.Status, formatTime(scan.StartedAt), formatTime(scan.FinishedAt), encodedScope); err != nil {
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
	for index, observation := range inventory.Observations {
		encoded, marshalErr := json.Marshal(observation)
		if marshalErr != nil {
			return fmt.Errorf("encode observation %q: %w", observation.ID, marshalErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO observations(scan_id, observation_id, asset_id, observation_json) VALUES (?, ?, ?, ?)`,
			scan.ScanID, observation.ID, observation.AssetID, encoded); err != nil {
			return fmt.Errorf("insert observation %q: %w", observation.ID, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO observation_state(scan_id, observation_id, observation_index, metadata_nil, consumers_nil) VALUES (?, ?, ?, ?, ?)`,
			scan.ScanID, observation.ID, index, boolInt(observation.Metadata == nil), boolInt(observation.Consumers == nil)); err != nil {
			return fmt.Errorf("insert observation state %q: %w", observation.ID, err)
		}
	}
	if err = saveEvidence(ctx, tx, scan.ScanID, inventory.Evidence); err != nil {
		return err
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
		encoded, marshalErr := encodeCoverage(result)
		if marshalErr != nil {
			return fmt.Errorf("encode coverage %q: %w", result.Collector, marshalErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO coverage(scan_id, collector, result_json) VALUES (?, ?, ?)`, scan.ScanID, result.Collector, encoded); err != nil {
			return fmt.Errorf("insert coverage %q: %w", result.Collector, err)
		}
	}
	if err = saveEvidenceCoverage(ctx, tx, scan.ScanID, scan.EvidenceCoverage); err != nil {
		return err
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO inventory_state(scan_id, assets_nil, relationships_nil, errors_nil, asset_count, relationship_count, error_count, observations_nil, observation_count, evidence_nil, evidence_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scan.ScanID, boolInt(inventory.Assets == nil), boolInt(inventory.Relationships == nil), boolInt(inventory.Errors == nil),
		len(inventory.Assets), len(inventory.Relationships), len(inventory.Errors), boolInt(inventory.Observations == nil), len(inventory.Observations),
		boolInt(inventory.Evidence == nil), len(inventory.Evidence)); err != nil {
		return fmt.Errorf("insert inventory state: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit snapshot transaction: %w", err)
	}
	return secureSQLiteFiles(s.path, guard)
}

// LatestInventory loads the inventory from the newest complete snapshot.
func (s *Store) LatestInventory(ctx context.Context) (model.Inventory, bool, error) {
	snapshot, ok, err := s.LatestSnapshot(ctx)
	return snapshot.Inventory, ok, err
}

// LatestSnapshot loads the newest scan and inventory by finished time,
// breaking ties by scan ID.
func (s *Store) LatestSnapshot(ctx context.Context) (model.Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, false, err
	}
	db, _, release, err := s.beginOperation()
	if err != nil {
		return model.Snapshot{}, false, err
	}
	defer release()
	var scan model.ScanResult
	var startedAt, finishedAt string
	var encodedScope []byte
	err = db.QueryRowContext(ctx, `SELECT id, schema_version, status, started_at, finished_at, scope_json FROM scans ORDER BY finished_at DESC, id DESC LIMIT 1`).
		Scan(&scan.ScanID, &scan.SchemaVersion, &scan.Status, &startedAt, &finishedAt, &encodedScope)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Snapshot{}, false, nil
	}
	if err != nil {
		return model.Snapshot{}, false, fmt.Errorf("select latest scan: %w", err)
	}
	if scan.StartedAt, err = parseTime(startedAt); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("decode started time for scan %q: %w", scan.ScanID, err)
	}
	if scan.FinishedAt, err = parseTime(finishedAt); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("decode finished time for scan %q: %w", scan.ScanID, err)
	}
	trimmedScope := bytes.TrimSpace(encodedScope)
	if len(trimmedScope) < 2 || trimmedScope[0] != '{' || trimmedScope[len(trimmedScope)-1] != '}' {
		return model.Snapshot{}, false, fmt.Errorf("decode scope for scan %q: scope must be a JSON object", scan.ScanID)
	}
	if err := decodeJSON(trimmedScope, &scan.Scope); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("decode scope for scan %q: %w", scan.ScanID, err)
	}
	if scan.Coverage, err = loadCoverage(ctx, db, scan.ScanID); err != nil {
		return model.Snapshot{}, false, err
	}
	if scan.EvidenceCoverage, err = loadEvidenceCoverage(ctx, db, scan.ScanID); err != nil {
		return model.Snapshot{}, false, err
	}

	var assetsNil, relationshipsNil, errorsNil, observationsNil, evidenceNil int
	var assetCount, relationshipCount, errorCount, observationCount, evidenceCount int
	if err := db.QueryRowContext(ctx, `SELECT assets_nil, relationships_nil, errors_nil, observations_nil, evidence_nil, asset_count, relationship_count, error_count, observation_count, evidence_count FROM inventory_state WHERE scan_id = ?`, scan.ScanID).
		Scan(&assetsNil, &relationshipsNil, &errorsNil, &observationsNil, &evidenceNil, &assetCount, &relationshipCount, &errorCount, &observationCount, &evidenceCount); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("load inventory state for scan %q: %w", scan.ScanID, err)
	}
	if err := validateBoolInts(assetsNil, relationshipsNil, errorsNil, observationsNil, evidenceNil); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: %w", scan.ScanID, err)
	}

	inventory := model.Inventory{}
	assets, err := loadAssets(ctx, db, scan.ScanID)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	if assetCount < 0 || len(assets) != assetCount {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: asset row count mismatch", scan.ScanID)
	}
	if assetsNil == 0 {
		inventory.Assets = assets
	} else if len(assets) != 0 {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: assets marked nil but rows exist", scan.ScanID)
	}
	assetIDs := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		assetIDs[asset.ID] = struct{}{}
	}
	observations, err := loadObservations(ctx, db, scan.ScanID, assetIDs)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	if observationCount < 0 || len(observations) != observationCount {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: observation row count mismatch", scan.ScanID)
	}
	if observationsNil == 0 {
		inventory.Observations = observations
	} else if len(observations) != 0 {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: observations marked nil but rows exist", scan.ScanID)
	}
	observationAssets := make(map[string]string, len(observations))
	for _, observation := range observations {
		observationAssets[observation.ID] = observation.AssetID
	}
	evidence, err := loadEvidence(ctx, db, scan.ScanID, assetIDs, observationAssets)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	if evidenceCount < 0 || len(evidence) != evidenceCount {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: evidence row count mismatch", scan.ScanID)
	}
	if evidenceNil == 0 {
		inventory.Evidence = evidence
	} else if len(evidence) != 0 {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: evidence marked nil but rows exist", scan.ScanID)
	}
	relationships, err := loadRelationships(ctx, db, scan.ScanID)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	if relationshipCount < 0 || len(relationships) != relationshipCount {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: relationship row count mismatch", scan.ScanID)
	}
	if relationshipsNil == 0 {
		inventory.Relationships = relationships
	} else if len(relationships) != 0 {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: relationships marked nil but rows exist", scan.ScanID)
	}
	inventoryErrors, err := loadInventoryErrors(ctx, db, scan.ScanID)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	if errorCount < 0 || len(inventoryErrors) != errorCount {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: error row count mismatch", scan.ScanID)
	}
	if errorsNil == 0 {
		inventory.Errors = inventoryErrors
	} else if len(inventoryErrors) != 0 {
		return model.Snapshot{}, false, fmt.Errorf("validate inventory state for scan %q: errors marked nil but rows exist", scan.ScanID)
	}
	if err := validateSnapshot(scan, inventory); err != nil {
		return model.Snapshot{}, false, fmt.Errorf("validate snapshot for scan %q: %w", scan.ScanID, err)
	}
	return model.Snapshot{Scan: scan, Inventory: inventory}, true, nil
}

func loadCoverage(ctx context.Context, db *sql.DB, scanID string) ([]model.CollectorResult, error) {
	rows, err := db.QueryContext(ctx, `SELECT collector, result_json FROM coverage WHERE scan_id = ? ORDER BY collector`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query coverage for scan %q: %w", scanID, err)
	}
	defer rows.Close()
	var coverage []model.CollectorResult
	for rows.Next() {
		var collector string
		var encoded []byte
		if err := rows.Scan(&collector, &encoded); err != nil {
			return nil, fmt.Errorf("scan coverage for scan %q: %w", scanID, err)
		}
		var persisted persistedCollectorResult
		if err := decodeJSON(encoded, &persisted); err != nil {
			return nil, fmt.Errorf("decode coverage %q for scan %q: %w", collector, scanID, err)
		}
		result := persisted.modelValue()
		if collector == "" || result.Collector != collector {
			return nil, fmt.Errorf("validate coverage %q for scan %q: JSON collector %q does not match row", collector, scanID, result.Collector)
		}
		coverage = append(coverage, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate coverage for scan %q: %w", scanID, err)
	}
	return coverage, nil
}

// persistedCollectorResult is deliberately separate from the public JSON
// representation. Database snapshots must distinguish nil from non-nil empty
// slices and maps, while report JSON may continue omitting empty values.
// LocalTargets is runtime-only and intentionally has no persistence field.
type persistedCollectorResult struct {
	Collector     string                    `json:"collector"`
	Status        model.CoverageStatus      `json:"status"`
	Assets        []persistedAsset          `json:"assets"`
	Relationships []model.Relationship      `json:"relationships"`
	Errors        []model.CoverageError     `json:"errors"`
	Targets       []persistedTargetCoverage `json:"targets"`
	Observations  []persistedObservation    `json:"observations"`
}

type persistedAsset struct {
	ID         string            `json:"id"`
	Type       model.AssetType   `json:"type"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Path       string            `json:"path,omitempty"`
	Source     string            `json:"source,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	ObservedAt time.Time         `json:"observedAt,omitempty,omitzero"`
	Metadata   map[string]string `json:"metadata"`
}

type persistedTargetCoverage struct {
	TargetID     string                `json:"targetId"`
	InstanceRef  string                `json:"instanceRef,omitempty"`
	Status       model.TargetStatus    `json:"status"`
	Assets       int                   `json:"assets"`
	Observations int                   `json:"observations"`
	Errors       []model.CoverageError `json:"errors"`
}

type persistedObservation struct {
	ID          string                 `json:"id"`
	AssetID     string                 `json:"assetId"`
	Collector   string                 `json:"collector"`
	Host        string                 `json:"host,omitempty"`
	Consumers   []string               `json:"consumers"`
	Scope       model.ObservationScope `json:"scope"`
	LocationRef string                 `json:"locationRef"`
	ProjectID   string                 `json:"projectId,omitempty"`
	Source      string                 `json:"source,omitempty"`
	Metadata    map[string]string      `json:"metadata"`
}

func encodeCoverage(result model.CollectorResult) ([]byte, error) {
	return json.Marshal(newPersistedCollectorResult(result))
}

func newPersistedCollectorResult(result model.CollectorResult) persistedCollectorResult {
	persisted := persistedCollectorResult{
		Collector:     result.Collector,
		Status:        result.Status,
		Relationships: result.Relationships,
		Errors:        result.Errors,
	}
	if result.Assets != nil {
		persisted.Assets = make([]persistedAsset, len(result.Assets))
		for index, asset := range result.Assets {
			persisted.Assets[index] = persistedAsset{
				ID: asset.ID, Type: asset.Type, Name: asset.Name, Version: asset.Version,
				Path: asset.Path, Source: asset.Source, SHA256: asset.SHA256,
				ObservedAt: asset.ObservedAt, Metadata: asset.Metadata,
			}
		}
	}
	if result.Targets != nil {
		persisted.Targets = make([]persistedTargetCoverage, len(result.Targets))
		for index, target := range result.Targets {
			persisted.Targets[index] = persistedTargetCoverage{
				TargetID: target.TargetID, InstanceRef: target.InstanceRef, Status: target.Status,
				Assets: target.Assets, Observations: target.Observations, Errors: target.Errors,
			}
		}
	}
	if result.Observations != nil {
		persisted.Observations = make([]persistedObservation, len(result.Observations))
		for index, observation := range result.Observations {
			persisted.Observations[index] = persistedObservation{
				ID: observation.ID, AssetID: observation.AssetID, Collector: observation.Collector,
				Host: observation.Host, Consumers: observation.Consumers, Scope: observation.Scope,
				LocationRef: observation.LocationRef, ProjectID: observation.ProjectID,
				Source: observation.Source, Metadata: observation.Metadata,
			}
		}
	}
	return persisted
}

func (persisted persistedCollectorResult) modelValue() model.CollectorResult {
	result := model.CollectorResult{
		Collector:     persisted.Collector,
		Status:        persisted.Status,
		Relationships: persisted.Relationships,
		Errors:        persisted.Errors,
	}
	if persisted.Assets != nil {
		result.Assets = make([]model.Asset, len(persisted.Assets))
		for index, asset := range persisted.Assets {
			result.Assets[index] = model.Asset{
				ID: asset.ID, Type: asset.Type, Name: asset.Name, Version: asset.Version,
				Path: asset.Path, Source: asset.Source, SHA256: asset.SHA256,
				ObservedAt: asset.ObservedAt, Metadata: asset.Metadata,
			}
		}
	}
	if persisted.Targets != nil {
		result.Targets = make([]model.TargetCoverage, len(persisted.Targets))
		for index, target := range persisted.Targets {
			result.Targets[index] = model.TargetCoverage{
				TargetID: target.TargetID, InstanceRef: target.InstanceRef, Status: target.Status,
				Assets: target.Assets, Observations: target.Observations, Errors: target.Errors,
			}
		}
	}
	if persisted.Observations != nil {
		result.Observations = make([]model.Observation, len(persisted.Observations))
		for index, observation := range persisted.Observations {
			result.Observations[index] = model.Observation{
				ID: observation.ID, AssetID: observation.AssetID, Collector: observation.Collector,
				Host: observation.Host, Consumers: observation.Consumers, Scope: observation.Scope,
				LocationRef: observation.LocationRef, ProjectID: observation.ProjectID,
				Source: observation.Source, Metadata: observation.Metadata,
			}
		}
	}
	return result
}

func loadAssets(ctx context.Context, db *sql.DB, scanID string) ([]model.Asset, error) {
	rows, err := db.QueryContext(ctx, `SELECT a.asset_id, a.asset_json, st.asset_index, st.metadata_nil
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

func loadObservations(ctx context.Context, db *sql.DB, scanID string, assetIDs map[string]struct{}) ([]model.Observation, error) {
	rows, err := db.QueryContext(ctx, `SELECT o.observation_id, o.asset_id, o.observation_json,
       st.observation_index, st.metadata_nil, st.consumers_nil
FROM observations o LEFT JOIN observation_state st
ON st.scan_id = o.scan_id AND st.observation_id = o.observation_id
WHERE o.scan_id = ? ORDER BY st.observation_index`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query observations for scan %q: %w", scanID, err)
	}
	defer rows.Close()
	observations := make([]model.Observation, 0)
	expectedIndex := 0
	for rows.Next() {
		var observationID, assetID string
		var encoded []byte
		var index, metadataNil, consumersNil sql.NullInt64
		if err := rows.Scan(&observationID, &assetID, &encoded, &index, &metadataNil, &consumersNil); err != nil {
			return nil, fmt.Errorf("scan observation for scan %q: %w", scanID, err)
		}
		if !index.Valid || !metadataNil.Valid || !consumersNil.Valid {
			return nil, fmt.Errorf("validate observation %q for scan %q: missing observation state", observationID, scanID)
		}
		if index.Int64 != int64(expectedIndex) {
			return nil, fmt.Errorf("validate observations for scan %q: got index %d, want %d", scanID, index.Int64, expectedIndex)
		}
		if _, ok := assetIDs[assetID]; !ok {
			return nil, fmt.Errorf("validate observation %q for scan %q: row references missing asset %q", observationID, scanID, assetID)
		}
		var observation model.Observation
		if err := decodeJSON(encoded, &observation); err != nil {
			return nil, fmt.Errorf("decode observation %q for scan %q: %w", observationID, scanID, err)
		}
		if observationID == "" || observation.ID != observationID {
			return nil, fmt.Errorf("validate observation %q for scan %q: JSON id %q does not match row", observationID, scanID, observation.ID)
		}
		if assetID == "" || observation.AssetID != assetID {
			return nil, fmt.Errorf("validate observation %q for scan %q: JSON asset id %q does not match row", observationID, scanID, observation.AssetID)
		}
		if err := validateBoolInt64(metadataNil.Int64, consumersNil.Int64); err != nil {
			return nil, fmt.Errorf("validate observation %q for scan %q: %w", observationID, scanID, err)
		}
		if metadataNil.Int64 == 1 && observation.Metadata != nil {
			return nil, fmt.Errorf("validate observation %q for scan %q: metadata marked nil but JSON contains metadata", observationID, scanID)
		}
		if metadataNil.Int64 == 0 && observation.Metadata == nil {
			observation.Metadata = map[string]string{}
		}
		if consumersNil.Int64 == 1 && observation.Consumers != nil {
			return nil, fmt.Errorf("validate observation %q for scan %q: consumers marked nil but JSON contains consumers", observationID, scanID)
		}
		if consumersNil.Int64 == 0 && observation.Consumers == nil {
			observation.Consumers = []string{}
		}
		observations = append(observations, observation)
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate observations for scan %q: %w", scanID, err)
	}
	return observations, nil
}

func loadRelationships(ctx context.Context, db *sql.DB, scanID string) ([]model.Relationship, error) {
	rows, err := db.QueryContext(ctx, `SELECT r.from_id, r.to_id, r.kind, st.relationship_index
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

func loadInventoryErrors(ctx context.Context, db *sql.DB, scanID string) ([]model.CoverageError, error) {
	rows, err := db.QueryContext(ctx, `SELECT error_index, error_json FROM inventory_errors WHERE scan_id = ? ORDER BY error_index`, scanID)
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

func validateBoolInt64(values ...int64) error {
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

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}
