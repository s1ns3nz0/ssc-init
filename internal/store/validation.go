package store

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/privacy"
)

// ErrSensitiveSnapshot is returned without field or value details when a
// snapshot contains a high-confidence credential shape.
var ErrSensitiveSnapshot = errors.New("snapshot contains sensitive data")

var safeKeyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func validateSnapshot(scan model.ScanResult, inventory model.Inventory) error {
	for field, value := range map[string]string{
		"scan schema version": scan.SchemaVersion,
		"scan id":             scan.ScanID,
		"scan status":         scan.Status,
	} {
		if err := validateRequiredString(field, value); err != nil {
			return err
		}
	}
	if scan.StartedAt.IsZero() || scan.FinishedAt.IsZero() || scan.FinishedAt.Before(scan.StartedAt) {
		return errors.New("invalid scan timestamps")
	}
	for field, value := range map[string]string{
		"scan scope platform":        scan.Scope.Platform,
		"scan scope catalog version": scan.Scope.CatalogVersion,
	} {
		if err := validateOptionalString(field, value); err != nil {
			return err
		}
	}
	for _, projectRoot := range scan.Scope.ProjectRoots {
		if err := validateOptionalString("scan scope project root", projectRoot); err != nil {
			return err
		}
	}

	assetIDs := make(map[string]struct{}, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		if err := validateAsset(asset); err != nil {
			return err
		}
		if _, duplicate := assetIDs[asset.ID]; duplicate {
			return errors.New("duplicate inventory asset id")
		}
		assetIDs[asset.ID] = struct{}{}
	}
	relationships := make(map[model.Relationship]struct{}, len(inventory.Relationships))
	for _, relationship := range inventory.Relationships {
		if err := validateRelationship(relationship); err != nil {
			return err
		}
		if _, ok := assetIDs[relationship.From]; !ok {
			return errors.New("inventory relationship references missing source asset")
		}
		if _, ok := assetIDs[relationship.To]; !ok {
			return errors.New("inventory relationship references missing target asset")
		}
		if _, duplicate := relationships[relationship]; duplicate {
			return errors.New("duplicate inventory relationship")
		}
		relationships[relationship] = struct{}{}
	}
	for _, inventoryError := range inventory.Errors {
		if err := validateCoverageError(inventoryError); err != nil {
			return err
		}
	}
	observationIDs := make(map[string]struct{}, len(inventory.Observations))
	for _, observation := range inventory.Observations {
		if err := validateObservation(observation); err != nil {
			return err
		}
		if _, ok := assetIDs[observation.AssetID]; !ok {
			return errors.New("inventory observation references missing asset")
		}
		if _, duplicate := observationIDs[observation.ID]; duplicate {
			return errors.New("duplicate inventory observation id")
		}
		observationIDs[observation.ID] = struct{}{}
	}

	collectors := make(map[string]struct{}, len(scan.Coverage))
	for _, result := range scan.Coverage {
		if err := validateRequiredString("coverage collector", result.Collector); err != nil {
			return err
		}
		if !validCoverageStatus(result.Status) {
			return errors.New("invalid coverage status")
		}
		if _, duplicate := collectors[result.Collector]; duplicate {
			return errors.New("duplicate coverage collector")
		}
		collectors[result.Collector] = struct{}{}
		resultAssets := make(map[string]model.Asset, len(result.Assets))
		for _, asset := range result.Assets {
			if err := validateAsset(asset); err != nil {
				return err
			}
			if existing, duplicate := resultAssets[asset.ID]; duplicate && !reflect.DeepEqual(existing, asset) {
				return errors.New("conflicting coverage asset id")
			}
			resultAssets[asset.ID] = asset
		}
		resultRelationships := make(map[model.Relationship]struct{}, len(result.Relationships))
		for _, relationship := range result.Relationships {
			if err := validateRelationship(relationship); err != nil {
				return err
			}
			if _, duplicate := resultRelationships[relationship]; duplicate {
				return errors.New("duplicate coverage relationship")
			}
			resultRelationships[relationship] = struct{}{}
		}
		for _, coverageError := range result.Errors {
			if err := validateCoverageError(coverageError); err != nil {
				return err
			}
		}
		resultObservationIDs := make(map[string]struct{}, len(result.Observations))
		for _, observation := range result.Observations {
			if err := validateObservation(observation); err != nil {
				return err
			}
			if _, ok := resultAssets[observation.AssetID]; !ok {
				return errors.New("coverage observation references missing asset")
			}
			if _, duplicate := resultObservationIDs[observation.ID]; duplicate {
				return errors.New("duplicate coverage observation id")
			}
			resultObservationIDs[observation.ID] = struct{}{}
		}
		for _, target := range result.Targets {
			if err := validateRequiredString("target id", target.TargetID); err != nil {
				return err
			}
			if err := validateOptionalString("target instance reference", target.InstanceRef); err != nil {
				return err
			}
			if !validTargetStatus(target.Status) {
				return errors.New("invalid target status")
			}
			if target.Assets < 0 || target.Observations < 0 {
				return errors.New("invalid target counts")
			}
			for _, targetError := range target.Errors {
				if err := validateCoverageError(targetError); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateAsset(asset model.Asset) error {
	if err := validateRequiredString("asset id", asset.ID); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"asset type": string(asset.Type), "asset name": asset.Name, "asset version": asset.Version,
		"asset path": asset.Path, "asset source": asset.Source, "asset sha256": asset.SHA256,
	} {
		if err := validateOptionalString(field, value); err != nil {
			return err
		}
	}
	return validateMetadata("asset", asset.Metadata)
}

func validateObservation(observation model.Observation) error {
	for field, value := range map[string]string{
		"observation id":           observation.ID,
		"observation asset id":     observation.AssetID,
		"observation collector":    observation.Collector,
		"observation scope":        string(observation.Scope),
		"observation location ref": observation.LocationRef,
	} {
		if err := validateRequiredString(field, value); err != nil {
			return err
		}
	}
	if !validObservationScope(observation.Scope) {
		return errors.New("invalid observation scope")
	}
	for field, value := range map[string]string{
		"observation host":       observation.Host,
		"observation project id": observation.ProjectID,
		"observation source":     observation.Source,
	} {
		if err := validateOptionalString(field, value); err != nil {
			return err
		}
	}
	for index, consumer := range observation.Consumers {
		if err := validateOptionalString("observation consumer", consumer); err != nil {
			return err
		}
		if index > 0 && observation.Consumers[index-1] >= consumer {
			return errors.New("observation consumers must be sorted and unique")
		}
	}
	return validateMetadata("observation", observation.Metadata)
}

func validateMetadata(owner string, metadata map[string]string) error {
	for key, value := range metadata {
		if err := validateOptionalString(owner+" metadata key", key); err != nil {
			return err
		}
		if safeListMetadataKey(key) {
			if err := validateSafeKeyList(value); err != nil {
				return ErrSensitiveSnapshot
			}
		} else if metadataKeyCarriesSecret(key) && value != "" && !privacy.IsRedactedPlaceholder(value) {
			return ErrSensitiveSnapshot
		}
		if err := validateOptionalString(owner+" metadata value", value); err != nil {
			return err
		}
	}
	return nil
}

func validateRelationship(relationship model.Relationship) error {
	for field, value := range map[string]string{
		"relationship from": relationship.From,
		"relationship kind": relationship.Kind,
		"relationship to":   relationship.To,
	} {
		if err := validateRequiredString(field, value); err != nil {
			return err
		}
	}
	return nil
}

func validateCoverageError(coverageError model.CoverageError) error {
	if err := validateRequiredString("coverage error code", coverageError.Code); err != nil {
		return err
	}
	if err := validateRequiredString("coverage error message", coverageError.Message); err != nil {
		return err
	}
	return validateOptionalString("coverage error path", coverageError.Path)
}

func validateRequiredString(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	return validateOptionalString(field, value)
}

func validateOptionalString(field, value string) error {
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s is not valid text", field)
	}
	if privacy.ContainsSensitiveValue(value) {
		return ErrSensitiveSnapshot
	}
	return nil
}

func metadataKeyCarriesSecret(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	for _, safe := range []string{"env_keys", "environment_keys", "token_keys", "secret_keys", "credential_keys"} {
		if normalized == safe {
			return false
		}
	}
	for _, marker := range []string{"token", "secret", "password", "passwd", "credential", "authorization", "api_key", "access_key", "raw_env", "environment_value", "env_value"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	if normalized == "env" || normalized == "environment" || normalized == "env_vars" || normalized == "environment_variables" {
		return true
	}
	return false
}

func safeListMetadataKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	switch normalized {
	case "env_keys", "environment_keys", "token_keys", "secret_keys", "credential_keys":
		return true
	default:
		return false
	}
}

func validateSafeKeyList(value string) error {
	if privacy.IsRedactedPlaceholder(value) {
		return nil
	}
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\t =;:/?#&") || privacy.ContainsSensitiveValue(value) {
		return ErrSensitiveSnapshot
	}
	items := strings.Split(value, ",")
	if len(items) > 128 {
		return ErrSensitiveSnapshot
	}
	for _, item := range items {
		if !safeKeyName.MatchString(item) {
			return ErrSensitiveSnapshot
		}
	}
	return nil
}

func validCoverageStatus(status model.CoverageStatus) bool {
	switch status {
	case model.CoverageComplete, model.CoveragePartial, model.CoverageSkipped, model.CoverageUnavailable, model.CoverageFailed:
		return true
	default:
		return false
	}
}

func validObservationScope(scope model.ObservationScope) bool {
	switch scope {
	case model.ScopeUser, model.ScopeProject, model.ScopeIDEProfile, model.ScopeToolEnvironment, model.ScopeSystem:
		return true
	default:
		return false
	}
}

func validTargetStatus(status model.TargetStatus) bool {
	switch status {
	case model.TargetComplete, model.TargetNotPresent, model.TargetPartial, model.TargetUnavailable, model.TargetUnsupported, model.TargetSkipped:
		return true
	default:
		return false
	}
}
