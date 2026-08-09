package quarantine

import (
	"encoding/hex"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

type State string

const (
	StateRequested   State = "requested"
	StateQuarantined State = "quarantined"
	StateRestored    State = "restored"
	StateFailed      State = "failed"
)

type FailureCode string

const (
	FailureIdentityChanged    FailureCode = "identity-changed"
	FailureUnavailable        FailureCode = "unavailable"
	FailureCollision          FailureCode = "collision"
	FailureCancelled          FailureCode = "cancelled"
	FailureVerificationFailed FailureCode = "verification-failed"
)

type Record struct {
	ID            string      `json:"id"`
	AssetID       string      `json:"assetId"`
	ObservationID string      `json:"observationId"`
	EvidenceID    string      `json:"evidenceId"`
	OriginalRef   string      `json:"originalRef"`
	SHA256        string      `json:"sha256"`
	OriginalMode  uint32      `json:"originalMode"`
	State         State       `json:"state"`
	FailureCode   FailureCode `json:"failureCode,omitempty"`
	RequestedAt   time.Time   `json:"requestedAt"`
	QuarantinedAt time.Time   `json:"quarantinedAt,omitempty"`
	RestoredAt    time.Time   `json:"restoredAt,omitempty"`
}

func (r Record) Valid() bool {
	if !safeID(r.ID) || !safeID(r.AssetID) || !safeID(r.ObservationID) || !safeID(r.EvidenceID) || !tokenizedRef(r.OriginalRef) || !sha256Value(r.SHA256) || r.OriginalMode > 0o777 || r.RequestedAt.IsZero() {
		return false
	}
	switch r.State {
	case StateRequested:
		return r.FailureCode == "" && r.QuarantinedAt.IsZero() && r.RestoredAt.IsZero()
	case StateQuarantined:
		return r.FailureCode == "" && !r.QuarantinedAt.Before(r.RequestedAt) && !r.QuarantinedAt.IsZero() && r.RestoredAt.IsZero()
	case StateRestored:
		return r.FailureCode == "" && !r.QuarantinedAt.IsZero() && !r.QuarantinedAt.Before(r.RequestedAt) && !r.RestoredAt.IsZero() && !r.RestoredAt.Before(r.QuarantinedAt)
	case StateFailed:
		return validFailureCode(r.FailureCode) && r.QuarantinedAt.IsZero() && r.RestoredAt.IsZero()
	default:
		return false
	}
}

func validFailureCode(value FailureCode) bool {
	switch value {
	case FailureIdentityChanged, FailureUnavailable, FailureCollision, FailureCancelled, FailureVerificationFailed:
		return true
	default:
		return false
	}
}

func sha256Value(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func tokenizedRef(value string) bool {
	var relative string
	switch {
	case strings.HasPrefix(value, "$HOME/"):
		relative = strings.TrimPrefix(value, "$HOME/")
	case strings.HasPrefix(value, "$PROJECT/"):
		relative = strings.TrimPrefix(value, "$PROJECT/")
	default:
		return false
	}
	return relative != "" && path.Clean(relative) == relative && relative != "." && !strings.HasPrefix(relative, "../") && !privacy.ContainsSensitiveValue(value)
}

func safeID(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || privacy.ContainsSensitiveValue(value) {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) || unicode.IsSpace(current) {
			return false
		}
	}
	return true
}
