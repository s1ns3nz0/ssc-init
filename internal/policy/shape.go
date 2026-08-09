package policy

import (
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func matchesShape(match Match, asset model.Asset, observation model.Observation, evidence []model.ContentEvidence) bool {
	if !matchesSet(match.AssetType, string(asset.Type)) ||
		!matchesSet(match.AssetName, asset.Name) ||
		!matchesSet(match.AssetVersion, asset.Version) ||
		!matchesSet(match.Host, observation.Host) ||
		!matchesSet(match.ObservationSource, observation.Source) {
		return false
	}
	for key, values := range match.MetadataEquals {
		if !matchesSet(values, metadataValue(asset, observation, key)) {
			return false
		}
	}
	for key, values := range match.MetadataContains {
		if !containsAny(metadataValue(asset, observation, key), values, key == "args") {
			return false
		}
	}
	if len(match.EvidenceStatus) > 0 {
		matched := false
		for _, item := range evidence {
			if matchesSet(match.EvidenceStatus, string(item.Status)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchesSet(values []string, value string) bool {
	if len(values) == 0 {
		return true
	}
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func metadataValue(asset model.Asset, observation model.Observation, key string) string {
	if value, present := observation.Metadata[key]; present {
		return value
	}
	return asset.Metadata[key]
}

func containsAny(value string, fragments []string, splitArguments bool) bool {
	values := []string{value}
	if splitArguments {
		values = strings.Split(value, "\x1f")
	}
	for _, candidate := range values {
		for _, fragment := range fragments {
			if strings.Contains(candidate, fragment) {
				return true
			}
		}
	}
	return false
}
