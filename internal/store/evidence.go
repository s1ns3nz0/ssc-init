package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
)

const maxPersistedEvidenceErrors = 64

// persistedEvidenceCoverage is deliberately separate from the public JSON
// representation. Database snapshots must distinguish nil from non-nil empty
// slices, while report JSON may continue omitting empty values.
type persistedEvidenceCoverage struct {
	Status  model.CoverageStatus            `json:"status"`
	Targets []persistedEvidenceTargetResult `json:"targets"`
	Errors  []model.CoverageError           `json:"errors"`
}

type persistedEvidenceTargetResult struct {
	TargetID      string                `json:"targetId"`
	AssetID       string                `json:"assetId"`
	ObservationID string                `json:"observationId"`
	EvidenceID    string                `json:"evidenceId"`
	Status        model.EvidenceStatus  `json:"status"`
	Errors        []model.EvidenceError `json:"errors"`
}

func encodeEvidenceCoverage(coverage model.EvidenceCoverage) ([]byte, error) {
	persisted := persistedEvidenceCoverage{Status: coverage.Status, Errors: coverage.Errors}
	if coverage.Targets != nil {
		persisted.Targets = make([]persistedEvidenceTargetResult, len(coverage.Targets))
		for index, target := range coverage.Targets {
			persisted.Targets[index] = persistedEvidenceTargetResult{
				TargetID: target.TargetID, AssetID: target.AssetID, ObservationID: target.ObservationID,
				EvidenceID: target.EvidenceID, Status: target.Status, Errors: target.Errors,
			}
		}
	}
	return json.Marshal(persisted)
}

func (persisted persistedEvidenceCoverage) modelValue() model.EvidenceCoverage {
	coverage := model.EvidenceCoverage{Status: persisted.Status, Errors: persisted.Errors}
	if persisted.Targets != nil {
		coverage.Targets = make([]model.EvidenceTargetResult, len(persisted.Targets))
		for index, target := range persisted.Targets {
			coverage.Targets[index] = model.EvidenceTargetResult{
				TargetID: target.TargetID, AssetID: target.AssetID, ObservationID: target.ObservationID,
				EvidenceID: target.EvidenceID, Status: target.Status, Errors: target.Errors,
			}
		}
	}
	return coverage
}

func evidenceCoverageIsZero(coverage model.EvidenceCoverage) bool {
	return coverage.Status == "" && coverage.Targets == nil && coverage.Errors == nil
}

func saveEvidence(ctx context.Context, tx *sql.Tx, scanID string, evidence []model.ContentEvidence) error {
	for index, record := range evidence {
		encoded, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode evidence %q: %w", record.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence(scan_id, evidence_id, asset_id, observation_id, evidence_json) VALUES (?, ?, ?, ?, ?)`,
			scanID, record.ID, record.AssetID, record.ObservationID, encoded); err != nil {
			return fmt.Errorf("insert evidence %q: %w", record.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_state(scan_id, evidence_id, evidence_index, metadata_nil, errors_nil) VALUES (?, ?, ?, ?, ?)`,
			scanID, record.ID, index, boolInt(record.Metadata == nil), boolInt(record.Errors == nil)); err != nil {
			return fmt.Errorf("insert evidence state %q: %w", record.ID, err)
		}
	}
	return nil
}

func saveEvidenceCoverage(ctx context.Context, tx *sql.Tx, scanID string, coverage model.EvidenceCoverage) error {
	if evidenceCoverageIsZero(coverage) {
		return nil
	}
	encoded, err := encodeEvidenceCoverage(coverage)
	if err != nil {
		return fmt.Errorf("encode evidence coverage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_coverage(scan_id, result_json) VALUES (?, ?)`, scanID, encoded); err != nil {
		return fmt.Errorf("insert evidence coverage: %w", err)
	}
	return nil
}

func loadEvidence(ctx context.Context, db *sql.DB, scanID string, assetIDs map[string]struct{}, observationAssets map[string]string) ([]model.ContentEvidence, error) {
	rows, err := db.QueryContext(ctx, `SELECT e.evidence_id, e.asset_id, e.observation_id, e.evidence_json,
       st.evidence_index, st.metadata_nil, st.errors_nil
FROM evidence e LEFT JOIN evidence_state st
ON st.scan_id = e.scan_id AND st.evidence_id = e.evidence_id
WHERE e.scan_id = ? ORDER BY st.evidence_index`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query evidence for scan %q: %w", scanID, err)
	}
	defer rows.Close()
	evidence := make([]model.ContentEvidence, 0)
	expectedIndex := 0
	for rows.Next() {
		var evidenceID, assetID, observationID string
		var encoded []byte
		var index, metadataNil, errorsNil sql.NullInt64
		if err := rows.Scan(&evidenceID, &assetID, &observationID, &encoded, &index, &metadataNil, &errorsNil); err != nil {
			return nil, fmt.Errorf("scan evidence for scan %q: %w", scanID, err)
		}
		if !index.Valid || !metadataNil.Valid || !errorsNil.Valid {
			return nil, fmt.Errorf("validate evidence %q for scan %q: missing evidence state", evidenceID, scanID)
		}
		if index.Int64 != int64(expectedIndex) {
			return nil, fmt.Errorf("validate evidence for scan %q: got index %d, want %d", scanID, index.Int64, expectedIndex)
		}
		if _, ok := assetIDs[assetID]; !ok {
			return nil, fmt.Errorf("validate evidence %q for scan %q: row references missing asset %q", evidenceID, scanID, assetID)
		}
		if ownerAsset, ok := observationAssets[observationID]; !ok || ownerAsset != assetID {
			return nil, fmt.Errorf("validate evidence %q for scan %q: row references missing observation %q", evidenceID, scanID, observationID)
		}
		var record model.ContentEvidence
		if err := decodeJSON(encoded, &record); err != nil {
			return nil, fmt.Errorf("decode evidence %q for scan %q: %w", evidenceID, scanID, err)
		}
		if evidenceID == "" || record.ID != evidenceID {
			return nil, fmt.Errorf("validate evidence %q for scan %q: JSON id %q does not match row", evidenceID, scanID, record.ID)
		}
		if assetID == "" || record.AssetID != assetID {
			return nil, fmt.Errorf("validate evidence %q for scan %q: JSON asset id %q does not match row", evidenceID, scanID, record.AssetID)
		}
		if observationID == "" || record.ObservationID != observationID {
			return nil, fmt.Errorf("validate evidence %q for scan %q: JSON observation id %q does not match row", evidenceID, scanID, record.ObservationID)
		}
		if err := validateBoolInt64(metadataNil.Int64, errorsNil.Int64); err != nil {
			return nil, fmt.Errorf("validate evidence %q for scan %q: %w", evidenceID, scanID, err)
		}
		if metadataNil.Int64 == 1 && record.Metadata != nil {
			return nil, fmt.Errorf("validate evidence %q for scan %q: metadata marked nil but JSON contains metadata", evidenceID, scanID)
		}
		if metadataNil.Int64 == 0 && record.Metadata == nil {
			record.Metadata = map[string]string{}
		}
		if errorsNil.Int64 == 1 && record.Errors != nil {
			return nil, fmt.Errorf("validate evidence %q for scan %q: errors marked nil but JSON contains errors", evidenceID, scanID)
		}
		if errorsNil.Int64 == 0 && record.Errors == nil {
			record.Errors = []model.EvidenceError{}
		}
		evidence = append(evidence, record)
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate evidence for scan %q: %w", scanID, err)
	}
	return evidence, nil
}

func loadEvidenceCoverage(ctx context.Context, db *sql.DB, scanID string) (model.EvidenceCoverage, error) {
	var encoded []byte
	err := db.QueryRowContext(ctx, `SELECT result_json FROM evidence_coverage WHERE scan_id = ?`, scanID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return model.EvidenceCoverage{}, nil
	}
	if err != nil {
		return model.EvidenceCoverage{}, fmt.Errorf("query evidence coverage for scan %q: %w", scanID, err)
	}
	var persisted persistedEvidenceCoverage
	if err := decodeJSON(encoded, &persisted); err != nil {
		return model.EvidenceCoverage{}, fmt.Errorf("decode evidence coverage for scan %q: %w", scanID, err)
	}
	coverage := persisted.modelValue()
	if evidenceCoverageIsZero(coverage) {
		return model.EvidenceCoverage{}, fmt.Errorf("validate evidence coverage for scan %q: stored coverage is empty", scanID)
	}
	return coverage, nil
}

func validateContentEvidence(value model.ContentEvidence, assetIDs map[string]struct{}, observationAssets map[string]string) error {
	for field, fieldValue := range map[string]string{
		"evidence id":             value.ID,
		"evidence asset id":       value.AssetID,
		"evidence observation id": value.ObservationID,
	} {
		if err := validateRequiredString(field, fieldValue); err != nil {
			return err
		}
	}
	if !validEvidenceKindSubject(value.Kind, value.Subject) {
		return errors.New("invalid evidence kind or subject")
	}
	if !validEvidenceStatus(value.Status) || !validEvidenceKindStatus(value.Kind, value.Status) {
		return errors.New("invalid evidence status")
	}
	if _, ok := assetIDs[value.AssetID]; !ok {
		return errors.New("evidence references missing asset")
	}
	ownerAsset, ok := observationAssets[value.ObservationID]
	if !ok {
		return errors.New("evidence references missing observation")
	}
	if ownerAsset != value.AssetID {
		return errors.New("evidence observation asset mismatch")
	}
	recomputed := value
	recomputed.ID = ""
	finalized, err := identity.FinalizeEvidence(recomputed)
	if err != nil || finalized.ID != value.ID {
		return errors.New("invalid evidence id")
	}
	if err := validateEvidenceShape(value); err != nil {
		return err
	}
	if err := validateEvidenceMetadata(value); err != nil {
		return err
	}
	return validateEvidenceErrors(value.Errors)
}

func validateEvidenceShape(value model.ContentEvidence) error {
	if value.Size < 0 || value.Files < 0 || value.Directories < 0 || value.Symlinks < 0 {
		return errors.New("invalid evidence counts")
	}
	switch value.Status {
	case model.EvidenceComplete:
		if value.Algorithm != "sha256" || !lowercaseSHA256Hex(value.Digest) {
			return errors.New("invalid evidence digest")
		}
		if len(value.Errors) != 0 {
			return errors.New("invalid evidence errors")
		}
	case model.EvidencePartial, model.EvidenceOversize:
		if len(value.Errors) == 0 {
			return errors.New("invalid evidence errors")
		}
		switch value.Kind {
		case model.EvidenceTreeSHA256:
			if value.Algorithm != "sha256" || !lowercaseSHA256Hex(value.Digest) {
				return errors.New("invalid evidence digest")
			}
		default:
			if (value.Algorithm != "" || value.Digest != "") && (value.Algorithm != "sha256" || !lowercaseSHA256Hex(value.Digest)) {
				return errors.New("invalid evidence digest")
			}
		}
	case model.EvidenceUnavailable:
		if len(value.Errors) == 0 {
			return errors.New("invalid evidence errors")
		}
		return validateTerminalEvidencePayload(value)
	default: // unsupported, skipped
		if len(value.Errors) != 0 {
			return errors.New("invalid evidence errors")
		}
		return validateTerminalEvidencePayload(value)
	}
	switch value.Kind {
	case model.EvidenceTreeSHA256:
	case model.EvidenceFileSHA256:
		if value.Files != 0 || value.Directories != 0 || value.Symlinks != 0 {
			return errors.New("invalid evidence counts")
		}
	default:
		if value.Size != 0 || value.Files != 0 || value.Directories != 0 || value.Symlinks != 0 {
			return errors.New("invalid evidence counts")
		}
	}
	return nil
}

func validateTerminalEvidencePayload(value model.ContentEvidence) error {
	if value.Algorithm != "" || value.Digest != "" || value.Size != 0 || value.Files != 0 || value.Directories != 0 || value.Symlinks != 0 || len(value.Metadata) != 0 {
		return errors.New("invalid evidence payload")
	}
	return nil
}

func validateEvidenceMetadata(value model.ContentEvidence) error {
	for key, metadataValue := range value.Metadata {
		switch key {
		case "completeness":
			expected := "complete"
			if value.Status != model.EvidenceComplete {
				expected = "observed-subset"
			}
			if metadataValue != expected {
				return errors.New("invalid evidence metadata")
			}
		case "cache":
			if value.Kind != model.EvidenceTreeSHA256 {
				return errors.New("invalid evidence metadata")
			}
			switch metadataValue {
			case "disabled", "hit", "miss", "rejected":
			default:
				return errors.New("invalid evidence metadata")
			}
		default:
			return errors.New("invalid evidence metadata")
		}
	}
	return nil
}

func validateEvidenceErrors(values []model.EvidenceError) error {
	if len(values) > maxPersistedEvidenceErrors {
		return errors.New("invalid evidence errors")
	}
	for _, value := range values {
		if err := validateRequiredString("evidence error code", value.Code); err != nil {
			return err
		}
		if err := validateRequiredString("evidence error message", value.Message); err != nil {
			return err
		}
		if err := validatePersistenceSafePath("evidence error code", value.Code); err != nil {
			return err
		}
		if err := validatePersistenceSafePath("evidence error message", value.Message); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceCoverageResult(coverage model.EvidenceCoverage, evidenceByID map[string]model.ContentEvidence) error {
	if evidenceCoverageIsZero(coverage) {
		return nil
	}
	if !validCoverageStatus(coverage.Status) {
		return errors.New("invalid evidence coverage status")
	}
	referenced := make(map[string]struct{}, len(coverage.Targets))
	for _, target := range coverage.Targets {
		if err := validateRequiredString("evidence target id", target.TargetID); err != nil {
			return err
		}
		record, ok := evidenceByID[target.EvidenceID]
		if !ok {
			return errors.New("evidence coverage references missing evidence")
		}
		if target.AssetID != record.AssetID || target.ObservationID != record.ObservationID {
			return errors.New("evidence coverage reference mismatch")
		}
		if target.Status != record.Status {
			return errors.New("evidence coverage status mismatch")
		}
		if _, duplicate := referenced[target.EvidenceID]; duplicate {
			return errors.New("duplicate evidence coverage target")
		}
		referenced[target.EvidenceID] = struct{}{}
		if err := validateEvidenceErrors(target.Errors); err != nil {
			return err
		}
	}
	for _, coverageError := range coverage.Errors {
		if err := validateCoverageError(coverageError); err != nil {
			return err
		}
	}
	return nil
}

func validEvidenceKindSubject(kind model.EvidenceKind, subject string) bool {
	switch kind {
	case model.EvidenceFileSHA256:
		return subject == model.EvidenceSubjectManifest || subject == model.EvidenceSubjectSkillDocument ||
			subject == model.EvidenceSubjectEntrypointMain || subject == model.EvidenceSubjectEntrypointBrowser ||
			model.ProjectEvidenceSubject(subject)
	case model.EvidenceTreeSHA256:
		return subject == model.EvidenceSubjectPayloadTree
	case model.EvidenceSemanticSHA256:
		return subject == model.EvidenceSubjectMCPDeclaration
	case model.EvidencePackageContent:
		return subject == model.EvidenceSubjectPackageContent
	case model.EvidenceContainerIdentity:
		return subject == model.EvidenceSubjectContainerImage
	default:
		return false
	}
}

func validEvidenceStatus(status model.EvidenceStatus) bool {
	switch status {
	case model.EvidenceComplete, model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable, model.EvidenceUnsupported, model.EvidenceSkipped:
		return true
	default:
		return false
	}
}

func validEvidenceKindStatus(kind model.EvidenceKind, status model.EvidenceStatus) bool {
	if kind == model.EvidencePackageContent || kind == model.EvidenceContainerIdentity {
		return status == model.EvidenceUnsupported || status == model.EvidenceSkipped
	}
	if status == model.EvidencePartial || status == model.EvidenceOversize {
		return kind == model.EvidenceFileSHA256 || kind == model.EvidenceTreeSHA256
	}
	return true
}

func lowercaseSHA256Hex(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
