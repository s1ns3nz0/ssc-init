package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	privacyboundary "github.com/s1ns3nz0/ssc-init/internal/privacy"
)

// Validate checks the closed audit envelope before it is stored or exported.
// Privacy-specific content checks and profile transformation follow in this file.
func Validate(record Record) error {
	if record.SchemaVersion != schemaVersion || !validProfile(record.Profile) || !validRecordRun(record.Profile, record.Run) || record.Summary != summarize(record) {
		return errors.New("invalid audit record")
	}
	if record.State == StateFailed {
		if record.Failure == nil || !validFailure(record.Failure.Stage, record.Failure.Code) || !emptyFailurePayload(record) {
			return errors.New("invalid failed audit record")
		}
		return validatePrivacy(record)
	}
	if (record.State != StateComplete && record.State != StatePartial) || record.Failure != nil {
		return errors.New("invalid completed audit record")
	}
	if containsOriginalErrorText(record) {
		return errors.New("audit record retains error detail")
	}
	if record.Profile == ProfileRedacted {
		if err := validateRedactedFields(record); err != nil {
			return err
		}
	}
	return validatePrivacy(record)
}

func validProfile(value Profile) bool { return value == ProfileInternal || value == ProfileRedacted }

func validRecordRun(profile Profile, run Run) bool {
	if !validRunIDs(profile, run) || !validRunText(profile, run) {
		return false
	}
	return !run.StartedAt.IsZero() && !run.FinishedAt.IsZero() && run.StartedAt.Location() == runUTC && run.FinishedAt.Location() == runUTC && !run.FinishedAt.Before(run.StartedAt)
}

var runUTC = normalizeRunTimestamp()

func normalizeRunTimestamp() *time.Location { return time.UTC }

func closedValue(value string) bool { return value != "" && len(value) <= 128 }

func validRunIDs(profile Profile, run Run) bool {
	if profile == ProfileInternal {
		return runIDPattern.MatchString(run.ID) && run.ScanID != "" && deviceIDPattern.MatchString(run.DeviceID)
	}
	return exportToken("run", run.ID) && exportToken("scan", run.ScanID) && exportToken("device", run.DeviceID)
}

func validRunText(profile Profile, run Run) bool {
	if profile == ProfileInternal {
		return ValidLabel(run.Label) && closedValue(run.Product) && closedValue(run.Version)
	}
	return run.Label == "redacted" && run.Product == "" && run.Version == ""
}

func exportToken(kind, value string) bool {
	prefix := kind + ":export-sha256:"
	if !strings.HasPrefix(value, prefix) || len(strings.TrimPrefix(value, prefix)) != 64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func emptyFailurePayload(record Record) bool {
	return len(record.Inventory.Assets) == 0 && len(record.Inventory.Observations) == 0 && len(record.Inventory.Evidence) == 0 &&
		len(record.Inventory.Relationships) == 0 && len(record.Inventory.Errors) == 0 && len(record.Inventory.Findings) == 0 && len(record.Inventory.AnalyzerFacts) == 0 &&
		len(record.Findings) == 0 && len(record.Coverage) == 0 &&
		record.EvidenceCoverage == nil && len(record.Changes.Changes) == 0
}

func containsOriginalErrorText(record Record) bool {
	if coverageErrorsContainText(record.Inventory.Errors) || evidenceContainsErrorText(record.Inventory.Evidence) {
		return true
	}
	for _, result := range record.Coverage {
		if coverageErrorsContainText(result.Errors) {
			return true
		}
		for _, target := range result.Targets {
			if coverageErrorsContainText(target.Errors) {
				return true
			}
		}
	}
	if record.EvidenceCoverage != nil {
		if coverageErrorsContainText(record.EvidenceCoverage.Errors) {
			return true
		}
		for _, target := range record.EvidenceCoverage.Targets {
			for _, evidenceError := range target.Errors {
				if evidenceError.Message != "" {
					return true
				}
			}
		}
	}
	return false
}

func coverageErrorsContainText(errors []model.CoverageError) bool {
	for _, coverageError := range errors {
		if coverageError.Message != "" || coverageError.Path != "" {
			return true
		}
	}
	return false
}

func evidenceContainsErrorText(evidence []model.ContentEvidence) bool {
	for _, item := range evidence {
		for _, evidenceError := range item.Errors {
			if evidenceError.Message != "" {
				return true
			}
		}
	}
	return false
}

// Redact produces an export-local record that cannot correlate inventory
// identities with another export. It never mutates the source record.
func Redact(record Record, salt [32]byte) (Record, error) {
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	redacted := clone(record)
	identities := map[string]string{}
	token := func(value string) string {
		if value == "" {
			return ""
		}
		if existing, ok := identities[value]; ok {
			return existing
		}
		mac := hmac.New(sha256.New, salt[:])
		_, _ = mac.Write([]byte(value))
		result := "asset:export-sha256:" + hex.EncodeToString(mac.Sum(nil))
		identities[value] = result
		return result
	}

	for index := range redacted.Inventory.Assets {
		redactAsset(&redacted.Inventory.Assets[index], token)
	}
	for index := range redacted.Coverage {
		redactCollector(&redacted.Coverage[index], token)
	}
	for index := range redacted.Inventory.Relationships {
		redacted.Inventory.Relationships[index].From = token(redacted.Inventory.Relationships[index].From)
		redacted.Inventory.Relationships[index].To = token(redacted.Inventory.Relationships[index].To)
	}
	for index := range redacted.Inventory.Observations {
		redactObservation(&redacted.Inventory.Observations[index], token)
	}
	for index := range redacted.Inventory.Evidence {
		redactEvidence(&redacted.Inventory.Evidence[index], token)
	}
	for index := range redacted.Inventory.Findings {
		redactFinding(&redacted.Inventory.Findings[index], token)
	}
	for index := range redacted.Inventory.AnalyzerFacts {
		fact := &redacted.Inventory.AnalyzerFacts[index]
		fact.ID = token(fact.ID)
		fact.AssetID = token(fact.AssetID)
		fact.EvidenceID = token(fact.EvidenceID)
	}
	for index := range redacted.Findings {
		redactFinding(&redacted.Findings[index], token)
	}
	for index := range redacted.Changes.Changes {
		redacted.Changes.Changes[index].EntityID = token(redacted.Changes.Changes[index].EntityID)
	}
	if redacted.EvidenceCoverage != nil {
		for index := range redacted.EvidenceCoverage.Targets {
			target := &redacted.EvidenceCoverage.Targets[index]
			target.TargetID = token(target.TargetID)
			target.AssetID = token(target.AssetID)
			target.ObservationID = token(target.ObservationID)
			target.EvidenceID = token(target.EvidenceID)
			clearEvidenceErrors(target.Errors)
		}
		clearCoverageErrors(redacted.EvidenceCoverage.Errors)
	}
	clearCoverageErrors(redacted.Inventory.Errors)
	redacted.Profile = ProfileRedacted
	redacted.Run.ID = exportIdentity("run", redacted.Run.ID, salt)
	redacted.Run.ScanID = exportIdentity("scan", redacted.Run.ScanID, salt)
	redacted.Run.DeviceID = exportIdentity("device", redacted.Run.DeviceID, salt)
	redacted.Run.Label, redacted.Run.Product, redacted.Run.Version = "redacted", "", ""
	normalizeRecord(&redacted)
	redacted.Summary = summarize(redacted)
	if err := Validate(redacted); err != nil {
		return Record{}, err
	}
	return redacted, nil
}

func exportIdentity(kind, value string, salt [32]byte) string {
	mac := hmac.New(sha256.New, salt[:])
	_, _ = mac.Write([]byte(value))
	return kind + ":export-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func redactAsset(asset *model.Asset, token func(string) string) {
	asset.ID = token(asset.ID)
	asset.Name, asset.Version, asset.Path, asset.Source, asset.SHA256 = "", "", "", "", ""
	asset.Metadata = nil
	if asset.Signature != nil {
		asset.Signature.Identifier, asset.Signature.TeamID = "", ""
	}
	if asset.Provenance != nil {
		asset.Provenance.Source, asset.Provenance.Integrity = "", ""
	}
}

func redactCollector(result *model.CollectorResult, token func(string) string) {
	for index := range result.Assets {
		redactAsset(&result.Assets[index], token)
	}
	for index := range result.Relationships {
		result.Relationships[index].From = token(result.Relationships[index].From)
		result.Relationships[index].To = token(result.Relationships[index].To)
	}
	for index := range result.Observations {
		redactObservation(&result.Observations[index], token)
	}
	for index := range result.Targets {
		result.Targets[index].TargetID = token(result.Targets[index].TargetID)
		result.Targets[index].InstanceRef = ""
		clearCoverageErrors(result.Targets[index].Errors)
	}
	clearCoverageErrors(result.Errors)
}

func redactObservation(observation *model.Observation, token func(string) string) {
	observation.ID, observation.AssetID = token(observation.ID), token(observation.AssetID)
	observation.Host, observation.LocationRef, observation.ProjectID, observation.Source = "", "", "", ""
	observation.Consumers, observation.Metadata = nil, nil
}

func redactEvidence(evidence *model.ContentEvidence, token func(string) string) {
	evidence.ID = token(evidence.ID)
	evidence.AssetID = token(evidence.AssetID)
	evidence.ObservationID = token(evidence.ObservationID)
	evidence.Digest, evidence.Metadata = "", nil
	for index := range evidence.Errors {
		evidence.Errors[index].Message = ""
	}
}

func redactFinding(finding *model.Finding, token func(string) string) {
	finding.ID, finding.AssetID = token(finding.ID), token(finding.AssetID)
	finding.Version, finding.SHA256 = "", ""
	for index := range finding.EvidenceIDs {
		finding.EvidenceIDs[index] = token(finding.EvidenceIDs[index])
	}
	for index := range finding.Bundles {
		finding.Bundles[index].Digest = ""
	}
}

func clearCoverageErrors(errors []model.CoverageError) {
	for index := range errors {
		errors[index].Message, errors[index].Path = "", ""
	}
}

func clearEvidenceErrors(errors []model.EvidenceError) {
	for index := range errors {
		errors[index].Message = ""
	}
}

func validateRedactedFields(record Record) error {
	for _, asset := range record.Inventory.Assets {
		if !redactedAsset(asset) {
			return errors.New("redacted audit record retains asset display identity")
		}
	}
	for _, result := range record.Coverage {
		for _, asset := range result.Assets {
			if !redactedAsset(asset) {
				return errors.New("redacted audit record retains asset display identity")
			}
		}
	}
	for _, finding := range append(append([]model.Finding(nil), record.Inventory.Findings...), record.Findings...) {
		if finding.Version != "" || finding.SHA256 != "" {
			return errors.New("redacted audit record retains finding display identity")
		}
		for _, bundle := range finding.Bundles {
			if bundle.Digest != "" {
				return errors.New("redacted audit record retains bundle digest")
			}
		}
	}
	for _, evidence := range record.Inventory.Evidence {
		if evidence.Digest != "" || len(evidence.Metadata) != 0 {
			return errors.New("redacted audit record retains evidence display identity")
		}
	}
	return nil
}

func redactedAsset(asset model.Asset) bool {
	return asset.Name == "" && asset.Version == "" && asset.Path == "" && asset.Source == "" && asset.SHA256 == "" && len(asset.Metadata) == 0 &&
		(asset.Signature == nil || asset.Signature.Identifier == "" && asset.Signature.TeamID == "") &&
		(asset.Provenance == nil || asset.Provenance.Source == "" && asset.Provenance.Integrity == "")
}

func validatePrivacy(record Record) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("invalid audit record")
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil || containsUnsafeValue(value) {
		return errors.New("audit record contains sensitive value")
	}
	return nil
}

func containsUnsafeValue(value any) bool {
	switch item := value.(type) {
	case string:
		return unsafeAuditString(item)
	case []any:
		for _, nested := range item {
			if containsUnsafeValue(nested) {
				return true
			}
		}
	case map[string]any:
		for key, nested := range item {
			if unsafeAuditString(key) || containsUnsafeValue(nested) {
				return true
			}
		}
	}
	return false
}

func unsafeAuditString(value string) bool {
	lower := strings.ToLower(value)
	return privacyboundary.ContainsSensitiveValue(value) || strings.HasPrefix(value, "/") || strings.Contains(value, `\`) ||
		strings.Contains(value, "://") || strings.Contains(lower, "/users/") || strings.Contains(lower, "worktree")
}
