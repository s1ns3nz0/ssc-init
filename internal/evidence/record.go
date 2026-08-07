package evidence

import (
	"encoding/hex"
	"strings"

	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
)

const (
	metadataCompleteness = "completeness"
	metadataCache        = "cache"
)

func validTrustedDigest(value model.ContentEvidence) bool {
	return value.Status == model.EvidenceComplete && value.Algorithm == "sha256" && lowercaseSHA256(value.Digest)
}

func lowercaseSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// finalizeRecord applies the closed public evidence contract and stable ID.
// Runtime anchors, paths, and provenance never enter the returned record.
func finalizeRecord(target model.LocalEvidenceTarget, value model.ContentEvidence) (model.ContentEvidence, error) {
	value.AssetID = target.AssetID
	value.ObservationID = target.ObservationID
	value.Kind = target.Kind
	value.Subject = target.Subject

	switch value.Status {
	case model.EvidenceComplete:
		if !validTrustedDigest(value) {
			value.Status = model.EvidenceUnavailable
			value.Algorithm = ""
			value.Digest = ""
			value.Size, value.Files, value.Directories, value.Symlinks = 0, 0, 0, 0
			value.Metadata = nil
			value.Errors = []model.EvidenceError{{Code: "read_unavailable", Message: "evidence collection is unavailable"}}
		} else {
			value.Metadata = controlledMetadata(value.Metadata, "complete")
		}
	case model.EvidencePartial, model.EvidenceOversize:
		value.Algorithm = ""
		value.Digest = ""
		value.Metadata = controlledMetadata(nil, "observed-subset")
	case model.EvidenceUnsupported, model.EvidenceSkipped:
		value.Algorithm = ""
		value.Digest = ""
		value.Size, value.Files, value.Directories, value.Symlinks = 0, 0, 0, 0
		value.Metadata = nil
	case model.EvidenceUnavailable:
		value.Algorithm = ""
		value.Digest = ""
		value.Size, value.Files, value.Directories, value.Symlinks = 0, 0, 0, 0
		value.Metadata = nil
	}
	return identity.FinalizeEvidence(value)
}

func controlledMetadata(metadata map[string]string, completeness string) map[string]string {
	result := map[string]string{metadataCompleteness: completeness}
	if cache, ok := metadata[metadataCache]; ok && validCacheMetadata(cache) {
		result[metadataCache] = cache
	}
	return result
}

func validCacheMetadata(value string) bool {
	switch value {
	case cacheDisabled, cacheHit, cacheMiss, cacheRejected:
		return true
	default:
		return false
	}
}
