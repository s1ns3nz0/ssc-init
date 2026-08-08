package evidence

import (
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
)

const (
	metadataCompleteness = "completeness"
	metadataCache        = "cache"
	maxRecordErrors      = 64
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

// finalizeRecord enforces the complete public record contract and never
// copies runtime target paths, anchors, or provenance into the result.
func finalizeRecord(target model.LocalEvidenceTarget, value model.ContentEvidence) (model.ContentEvidence, error) {
	if !validKindSubject(target.Kind, target.Subject) || !validKindStatus(target.Kind, value.Status) || !validAggregateShape(target.Kind, value) || !validRecordErrors(target.Kind, value.Errors) {
		return model.ContentEvidence{}, errors.New("evidence record rejected")
	}
	value.AssetID = target.AssetID
	value.ObservationID = target.ObservationID
	value.Kind = target.Kind
	value.Subject = target.Subject
	value.Errors = sortedEvidenceErrors(value.Errors)

	switch value.Status {
	case model.EvidenceComplete:
		if !validTrustedDigest(value) || len(value.Errors) != 0 {
			return model.ContentEvidence{}, errors.New("complete evidence record rejected")
		}
		value.Metadata = controlledMetadata(target.Kind, value.Metadata, "complete")
	case model.EvidencePartial, model.EvidenceOversize:
		if len(value.Errors) == 0 || !validSubsetDigest(target.Kind, value.Algorithm, value.Digest) {
			return model.ContentEvidence{}, errors.New("diagnostic evidence digest rejected")
		}
		value.Metadata = controlledMetadata(target.Kind, nil, "observed-subset")
	case model.EvidenceUnsupported, model.EvidenceSkipped:
		stripEvidencePayload(&value)
		value.Errors = nil
	case model.EvidenceUnavailable:
		stripEvidencePayload(&value)
		if len(value.Errors) == 0 {
			return model.ContentEvidence{}, errors.New("unavailable evidence requires an error")
		}
	default:
		return model.ContentEvidence{}, errors.New("evidence status rejected")
	}
	return identity.FinalizeEvidence(value)
}

func validKindStatus(kind model.EvidenceKind, status model.EvidenceStatus) bool {
	if kind == model.EvidencePackageContent || kind == model.EvidenceContainerIdentity {
		return status == model.EvidenceUnsupported || status == model.EvidenceSkipped
	}
	if status == model.EvidencePartial || status == model.EvidenceOversize {
		return kind == model.EvidenceFileSHA256 || kind == model.EvidenceTreeSHA256
	}
	switch status {
	case model.EvidenceComplete, model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable, model.EvidenceUnsupported, model.EvidenceSkipped:
		return true
	default:
		return false
	}
}

func validSubsetDigest(kind model.EvidenceKind, algorithm, digest string) bool {
	switch kind {
	case model.EvidenceTreeSHA256:
		return algorithm == "sha256" && lowercaseSHA256(digest)
	case model.EvidenceFileSHA256:
		return validDiagnosticDigest(algorithm, digest)
	default:
		return false
	}
}

func validAggregateShape(kind model.EvidenceKind, value model.ContentEvidence) bool {
	if value.Size < 0 || value.Files < 0 || value.Directories < 0 || value.Symlinks < 0 {
		return false
	}
	if value.Status == model.EvidenceUnsupported || value.Status == model.EvidenceSkipped || value.Status == model.EvidenceUnavailable {
		return true
	}
	switch kind {
	case model.EvidenceTreeSHA256:
		return true
	case model.EvidenceFileSHA256:
		return value.Files == 0 && value.Directories == 0 && value.Symlinks == 0
	default:
		return value.Size == 0 && value.Files == 0 && value.Directories == 0 && value.Symlinks == 0
	}
}

func validDiagnosticDigest(algorithm, digest string) bool {
	if algorithm == "" && digest == "" {
		return true
	}
	return algorithm == "sha256" && lowercaseSHA256(digest)
}

func validRecordErrors(kind model.EvidenceKind, values []model.EvidenceError) bool {
	if len(values) > maxRecordErrors {
		return false
	}
	for _, value := range values {
		if !validRecordError(value) || !validErrorKind(kind, value) {
			return false
		}
	}
	return true
}

func validErrorKind(kind model.EvidenceKind, value model.EvidenceError) bool {
	if strings.Contains(value.Message, "evidence file") {
		return kind == model.EvidenceFileSHA256 || kind == model.EvidenceTreeSHA256
	}
	if strings.Contains(value.Message, "evidence tree") {
		return kind == model.EvidenceTreeSHA256
	}
	return true
}

func validRecordError(value model.EvidenceError) bool {
	switch value.Code + "\x00" + value.Message {
	case "identity_changed\x00evidence file identity changed",
		"identity_changed\x00evidence tree identity changed",
		"identity_changed\x00evidence target identity changed",
		"symlink_rejected\x00symbolic link was not followed",
		"special_file_rejected\x00special file was not read",
		"byte_limit\x00evidence file exceeds the byte limit",
		"byte_limit\x00evidence tree exceeds the byte limit",
		"file_limit\x00evidence tree exceeds the entry limit",
		"depth_limit\x00evidence tree exceeds the depth limit",
		"time_limit\x00evidence tree deadline exceeded",
		"time_limit\x00evidence target deadline exceeded",
		"path_invalid\x00evidence tree path is invalid",
		"path_invalid\x00evidence target path is invalid",
		"read_unavailable\x00evidence file is unavailable",
		"read_unavailable\x00evidence tree entry is unavailable",
		"read_unavailable\x00evidence collection is unavailable":
		return true
	default:
		return false
	}
}

func sortedEvidenceErrors(values []model.EvidenceError) []model.EvidenceError {
	if values == nil {
		return nil
	}
	result := append([]model.EvidenceError(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Code != result[j].Code {
			return result[i].Code < result[j].Code
		}
		return result[i].Message < result[j].Message
	})
	return result
}

func stripEvidencePayload(value *model.ContentEvidence) {
	value.Algorithm = ""
	value.Digest = ""
	value.Size = 0
	value.Files = 0
	value.Directories = 0
	value.Symlinks = 0
	value.Metadata = nil
}

func controlledMetadata(kind model.EvidenceKind, metadata map[string]string, completeness string) map[string]string {
	result := map[string]string{metadataCompleteness: completeness}
	if kind == model.EvidenceTreeSHA256 {
		if cache, ok := metadata[metadataCache]; ok && validCacheMetadata(cache) {
			result[metadataCache] = cache
		}
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

func unavailableRecord(code, message string) model.ContentEvidence {
	return model.ContentEvidence{Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: code, Message: message}}}
}
