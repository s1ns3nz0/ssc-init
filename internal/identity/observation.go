package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

// ErrRejectedIdentity is returned when an observation identity field is empty
// or would persist sensitive data.
var ErrRejectedIdentity = errors.New("observation identity rejected")

// FinalizeObservation validates the privacy boundary, canonicalizes consumers,
// and assigns a deterministic ID derived from the canonical observation tuple.
func FinalizeObservation(value model.Observation) (model.Observation, error) {
	value.Consumers = uniqueSorted(value.Consumers)
	required := []string{value.AssetID, value.Collector, string(value.Scope), value.LocationRef}
	for _, field := range required {
		if field == "" || privacy.ContainsSensitiveValue(field) {
			return model.Observation{}, ErrRejectedIdentity
		}
	}
	for _, field := range append([]string{value.Host, value.ProjectID, value.Source}, value.Consumers...) {
		if privacy.ContainsSensitiveValue(field) {
			return model.Observation{}, ErrRejectedIdentity
		}
	}
	digest := sha256.Sum256(canonicalTuple(value))
	value.ID = fmt.Sprintf("observation:sha256:%x", digest)
	return value, nil
}

// SafeLocationRef returns a home-redacted path or a stable, non-revealing
// reference for a path outside home.
func SafeLocationRef(home, path, externalLabel string) string {
	return platform.SafeLocationRef(home, path, externalLabel)
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalTuple(value model.Observation) []byte {
	fields := []string{
		"ssc-init.observation.v1",
		value.AssetID,
		value.Collector,
		value.Host,
		string(value.Scope),
		value.LocationRef,
		value.ProjectID,
		value.Source,
	}
	output := make([]byte, 0)
	for _, field := range fields {
		output = appendLengthPrefixed(output, field)
	}
	output = appendUint32(output, uint32(len(value.Consumers)))
	for _, consumer := range value.Consumers {
		output = appendLengthPrefixed(output, consumer)
	}
	keys := make([]string, 0, len(value.Metadata))
	for key := range value.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output = appendUint32(output, uint32(len(keys)))
	for _, key := range keys {
		output = appendLengthPrefixed(output, key)
		output = appendLengthPrefixed(output, value.Metadata[key])
	}
	return output
}

func appendLengthPrefixed(output []byte, value string) []byte {
	output = appendUint32(output, uint32(len(value)))
	return append(output, value...)
}

func appendUint32(output []byte, value uint32) []byte {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], value)
	return append(output, buffer[:]...)
}
