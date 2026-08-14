// Package bundle validates signed threat-intelligence and organization-policy
// bundle contracts. Filesystem lifecycle and signature verification are kept
// in separate units so schema validation is deterministic and pure.
package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const SchemaVersion = "ssc-init.bundle.v1"

const maxBundleBytes = 16 << 20

var ErrMalformed = errors.New("bundle document is malformed")

type Family string

const (
	FamilyTI     Family = "ti"
	FamilyPolicy Family = "policy"
)

type Envelope struct {
	SchemaVersion string          `json:"schemaVersion"`
	Family        Family          `json:"family"`
	Version       string          `json:"version"`
	Sequence      uint64          `json:"sequence"`
	KeyID         string          `json:"keyId"`
	GeneratedAt   time.Time       `json:"generatedAt"`
	ValidFrom     time.Time       `json:"validFrom"`
	ValidUntil    time.Time       `json:"validUntil"`
	Payload       json.RawMessage `json:"payload"`
	TI            *TIPayload      `json:"-"`
	Policy        *PolicyPayload  `json:"-"`
}

type TIPayload struct {
	Records []TIRecord `json:"records"`
}

type TIRecord struct {
	ID               string   `json:"id"`
	AssetID          string   `json:"assetId"`
	VersionRange     string   `json:"versionRange,omitempty"`
	SHA256           string   `json:"sha256,omitempty"`
	Verdict          string   `json:"verdict"`
	Confidence       string   `json:"confidence"`
	SourceURLs       []string `json:"sourceUrls"`
	RetrievedAt      string   `json:"retrievedAt"`
	ValidUntil       string   `json:"validUntil"`
	Withdrawn        bool     `json:"withdrawn"`
	License          string   `json:"license"`
	Redistributable  bool     `json:"redistributable"`
	CampaignIDs      []string `json:"campaignIds,omitempty"`
	AttackTechniques []string `json:"attackTechniques,omitempty"`
}

type PolicyPayload struct {
	Denies     []PolicyRule      `json:"denies"`
	Allows     []PolicyAllow     `json:"allows"`
	Exceptions []PolicyException `json:"exceptions"`
	Tests      []PolicyTest      `json:"tests"`
	Retention  *Retention        `json:"retention,omitempty"`
}

type PolicyRule struct {
	ID      string `json:"id"`
	AssetID string `json:"assetId"`
}

type PolicyAllow struct {
	ID      string `json:"id"`
	AssetID string `json:"assetId"`
	SHA256  string `json:"sha256"`
}

type PolicyException struct {
	ID        string `json:"id"`
	RuleID    string `json:"ruleId"`
	AssetID   string `json:"assetId"`
	Approver  string `json:"approver"`
	Reason    string `json:"reason"`
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expiresAt"`
}

type PolicyTest struct {
	Name     string `json:"name"`
	AssetID  string `json:"assetId"`
	WantRule string `json:"wantRule,omitempty"`
}

type Retention struct {
	SnapshotsDays int `json:"snapshotsDays"`
	HistoryDays   int `json:"historyDays"`
	IncidentsDays int `json:"incidentsDays"`
}

func Load(raw []byte, now time.Time) (Envelope, error) {
	return loadEnvelope(raw, &now)
}

func loadEnvelope(raw []byte, now *time.Time) (Envelope, error) {
	if len(raw) == 0 || len(raw) > maxBundleBytes || hasDuplicateObjectKey(raw) {
		return Envelope{}, ErrMalformed
	}
	var envelope Envelope
	if err := decodeClosed(raw, &envelope); err != nil {
		return Envelope{}, ErrMalformed
	}
	if envelope.SchemaVersion != SchemaVersion || !validFamily(envelope.Family) ||
		envelope.Version == "" || len(envelope.Version) > 128 || envelope.Sequence == 0 ||
		envelope.KeyID == "" || len(envelope.KeyID) > 128 || envelope.GeneratedAt.IsZero() ||
		envelope.ValidFrom.IsZero() || envelope.ValidUntil.IsZero() ||
		envelope.ValidUntil.Before(envelope.ValidFrom) {
		return Envelope{}, ErrMalformed
	}
	if now != nil && (now.Before(envelope.ValidFrom) || now.After(envelope.ValidUntil)) {
		return Envelope{}, ErrMalformed
	}
	switch envelope.Family {
	case FamilyTI:
		var payload TIPayload
		if err := decodeClosed(envelope.Payload, &payload); err != nil || payload.Records == nil || validateTIPayload(payload) != nil {
			return Envelope{}, ErrMalformed
		}
		envelope.TI = &payload
	case FamilyPolicy:
		var payload PolicyPayload
		if err := decodeClosed(envelope.Payload, &payload); err != nil || payload.Denies == nil || payload.Allows == nil || payload.Exceptions == nil || payload.Tests == nil || validatePolicyPayload(payload, envelope.GeneratedAt) != nil {
			return Envelope{}, ErrMalformed
		}
		envelope.Policy = &payload
	}
	return envelope, nil
}

func validFamily(family Family) bool { return family == FamilyTI || family == FamilyPolicy }

func decodeClosed(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

func hasDuplicateObjectKey(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return false
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return true
				}
				if _, duplicate := seen[key]; duplicate {
					return true
				}
				seen[key] = struct{}{}
				if walk() {
					return true
				}
			}
			_, err = decoder.Token()
			return err != nil
		case '[':
			for decoder.More() {
				if walk() {
					return true
				}
			}
			_, err = decoder.Token()
			return err != nil
		default:
			return true
		}
	}
	if walk() {
		return true
	}
	_, err := decoder.Token()
	return err != io.EOF
}

type exactJSONFields map[string]exactJSONFields

// hasExactJSONFields rejects aliases accepted by encoding/json's
// case-insensitive struct matching. Nested object schemas are checked
// recursively when a field supplies a child schema.
func hasExactJSONFields(raw []byte, fields exactJSONFields) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		child, allowed := fields[key]
		if err != nil || !ok || !allowed {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
		if child != nil && !hasExactJSONFields(value, child) {
			return false
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}
