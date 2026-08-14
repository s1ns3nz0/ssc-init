package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	ManifestSchemaVersion = "ssc-init.ti-manifest.v1"
	maxManifestBytes      = 64 << 10
)

var manifestJSONFields = exactJSONFields{
	"schemaVersion": nil,
	"family":        nil,
	"version":       nil,
	"sequence":      nil,
	"keyId":         nil,
	"generatedAt":   nil,
	"validFrom":     nil,
	"validUntil":    nil,
	"length":        nil,
	"sha256":        nil,
	"releaseTag":    nil,
	"artifact":      nil,
}

type Manifest struct {
	SchemaVersion string    `json:"schemaVersion"`
	Family        Family    `json:"family"`
	Version       string    `json:"version"`
	Sequence      uint64    `json:"sequence"`
	KeyID         string    `json:"keyId"`
	GeneratedAt   time.Time `json:"generatedAt"`
	ValidFrom     time.Time `json:"validFrom"`
	ValidUntil    time.Time `json:"validUntil"`
	Length        int64     `json:"length"`
	SHA256        string    `json:"sha256"`
	ReleaseTag    string    `json:"releaseTag"`
	Artifact      string    `json:"artifact"`
}

type VerifiedManifest struct {
	Manifest Manifest
	Digest   [sha256.Size]byte
}

func LoadManifest(raw []byte, now time.Time) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes || hasDuplicateObjectKey(raw) || !hasExactJSONFields(raw, manifestJSONFields) {
		return Manifest{}, ErrMalformed
	}
	var manifest Manifest
	if err := decodeClosed(raw, &manifest); err != nil || !validManifest(manifest, now) {
		return Manifest{}, ErrMalformed
	}
	return manifest, nil
}

func VerifyManifest(raw, signature []byte, keys KeyRegistry, now time.Time) (VerifiedManifest, error) {
	manifest, err := LoadManifest(raw, now)
	if err != nil || len(signature) != ed25519.SignatureSize || testKeyID(manifest.KeyID) {
		return VerifiedManifest{}, ErrVerification
	}
	publicKey := keys[FamilyTI][manifest.KeyID]
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, raw, signature) {
		return VerifiedManifest{}, ErrVerification
	}
	return VerifiedManifest{Manifest: manifest, Digest: sha256.Sum256(raw)}, nil
}

func validManifest(manifest Manifest, now time.Time) bool {
	return manifest.SchemaVersion == ManifestSchemaVersion && manifest.Family == FamilyTI &&
		boundedPublicValue(manifest.Version, 128) && manifest.Sequence > 0 && boundedPublicValue(manifest.KeyID, 128) &&
		!manifest.GeneratedAt.IsZero() && !manifest.ValidFrom.IsZero() && !manifest.ValidUntil.IsZero() &&
		!manifest.GeneratedAt.Before(manifest.ValidFrom) && !manifest.GeneratedAt.After(manifest.ValidUntil) &&
		!manifest.ValidUntil.Before(manifest.ValidFrom) && !now.Before(manifest.ValidFrom) && !now.After(manifest.ValidUntil) &&
		manifest.Length > 0 && manifest.Length <= maxBundleBytes && validManifestSHA256(manifest.SHA256) &&
		manifest.ReleaseTag == fmt.Sprintf("ti-%08d", manifest.Sequence) && manifest.Artifact == "ti-bundle.json"
}

func validManifestSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func testKeyID(keyID string) bool { return strings.HasPrefix(strings.ToLower(keyID), "test") }
