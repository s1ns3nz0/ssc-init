package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVerifyManifestBindsImmutableReleaseArtifact(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "manifest fixture")
	raw := manifestFixture("ti-production-2026")
	signature := ed25519.Sign(privateKey, raw)
	verified, err := VerifyManifest(raw, signature, KeyRegistry{FamilyTI: {"ti-production-2026": publicKey}}, manifestNow())
	wantDigest := sha256.Sum256(raw)
	if err != nil || verified.Manifest.ReleaseTag != "ti-00000042" || verified.Manifest.Artifact != "ti-bundle.json" || verified.Digest != wantDigest {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
}

func TestVerifyManifestRejectsClosedSchemaAndImmutableLocatorMutations(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "manifest closed schema")
	valid := string(manifestFixture("ti-production-2026"))
	tests := map[string]string{
		"duplicate field":        strings.Replace(valid, `"family":"ti"`, `"family":"ti","family":"ti"`, 1),
		"unknown field":          strings.Replace(valid, `"artifact":`, `"extra":true,"artifact":`, 1),
		"wrong schema":           strings.Replace(valid, ManifestSchemaVersion, "ssc-init.ti-manifest.v2", 1),
		"wrong family":           strings.Replace(valid, `"family":"ti"`, `"family":"policy"`, 1),
		"traversal artifact":     strings.Replace(valid, `"ti-bundle.json"`, `"../ti-bundle.json"`, 1),
		"URL artifact":           strings.Replace(valid, `"ti-bundle.json"`, `"https://example.test/ti-bundle.json"`, 1),
		"mutable release":        strings.Replace(valid, `"ti-00000042"`, `"latest"`, 1),
		"noncanonical release":   strings.Replace(valid, `"ti-00000042"`, `"ti-42"`, 1),
		"release sequence drift": strings.Replace(valid, `"ti-00000042"`, `"ti-00000043"`, 1),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			raw := []byte(candidate)
			if _, err := VerifyManifest(raw, ed25519.Sign(privateKey, raw), KeyRegistry{FamilyTI: {"ti-production-2026": publicKey}}, manifestNow()); err != ErrVerification {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
}

func TestLoadManifestRejectsNoncanonicalAndCaseFoldDuplicateMemberNames(t *testing.T) {
	valid := string(manifestFixture("ti-production-2026"))
	for name, candidate := range map[string]string{
		"case alias":          strings.Replace(valid, `"family":"ti"`, `"Family":"ti"`, 1),
		"case fold duplicate": strings.Replace(valid, `"family":"ti"`, `"family":"policy","Family":"ti"`, 1),
		"key id alias":        strings.Replace(valid, `"keyId":"ti-production-2026"`, `"KeyId":"ti-production-2026"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadManifest([]byte(candidate), manifestNow()); err != ErrMalformed {
				t.Fatalf("noncanonical member accepted: %v", err)
			}
		})
	}
}

func TestVerifyManifestRejectsInvalidTimesDigestAndLengthBounds(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "manifest bounds")
	valid := string(manifestFixture("ti-production-2026"))
	tests := map[string]string{
		"future validity":  strings.Replace(valid, `"validFrom":"2026-08-13T23:00:00Z"`, `"validFrom":"2026-08-15T00:00:00Z"`, 1),
		"expired":          strings.Replace(valid, `"validUntil":"2026-08-21T00:00:00Z"`, `"validUntil":"2026-08-13T00:00:00Z"`, 1),
		"generated early":  strings.Replace(valid, `"generatedAt":"2026-08-14T00:00:00Z"`, `"generatedAt":"2026-08-13T22:00:00Z"`, 1),
		"generated late":   strings.Replace(valid, `"generatedAt":"2026-08-14T00:00:00Z"`, `"generatedAt":"2026-08-22T00:00:00Z"`, 1),
		"zero length":      strings.Replace(valid, `"length":1234`, `"length":0`, 1),
		"oversize length":  strings.Replace(valid, `"length":1234`, fmt.Sprintf(`"length":%d`, maxBundleBytes+1), 1),
		"short digest":     strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("a", 63), 1),
		"uppercase digest": strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			raw := []byte(candidate)
			if _, err := VerifyManifest(raw, ed25519.Sign(privateKey, raw), KeyRegistry{FamilyTI: {"ti-production-2026": publicKey}}, manifestNow()); err != ErrVerification {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
	oversize := append(manifestFixture("ti-production-2026"), make([]byte, maxManifestBytes)...)
	if _, err := LoadManifest(oversize, manifestNow()); err != ErrMalformed {
		t.Fatalf("oversize manifest err=%v", err)
	}
}

func TestVerifyManifestRejectsUnknownWrongFamilyAndTestKeys(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "manifest trust")
	for name, test := range map[string]struct {
		keyID string
		keys  KeyRegistry
	}{
		"unknown":      {"ti-production-2026", KeyRegistry{FamilyTI: {"other": publicKey}}},
		"wrong family": {"ti-production-2026", KeyRegistry{FamilyPolicy: {"ti-production-2026": publicKey}}},
		"test key":     {"test-ti-2026", KeyRegistry{FamilyTI: {"test-ti-2026": publicKey}}},
	} {
		t.Run(name, func(t *testing.T) {
			raw := manifestFixture(test.keyID)
			if _, err := VerifyManifest(raw, ed25519.Sign(privateKey, raw), test.keys, manifestNow()); err != ErrVerification {
				t.Fatalf("untrusted key accepted: %v", err)
			}
		})
	}
}

func TestVerifyManifestRejectsSignatureAndExactByteChanges(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "manifest exact bytes")
	raw := manifestFixture("ti-production-2026")
	signature := ed25519.Sign(privateKey, raw)
	changedSignature := append([]byte(nil), signature...)
	changedSignature[0] ^= 1
	changedRaw := append([]byte(nil), raw...)
	changedRaw = append(changedRaw, ' ')
	for _, candidate := range []struct{ raw, signature []byte }{
		{raw, changedSignature},
		{changedRaw, signature},
		{raw, signature[:len(signature)-1]},
	} {
		if _, err := VerifyManifest(candidate.raw, candidate.signature, KeyRegistry{FamilyTI: {"ti-production-2026": publicKey}}, manifestNow()); err != ErrVerification {
			t.Fatalf("changed signed material accepted: %v", err)
		}
	}
}

func manifestFixture(keyID string) []byte {
	return []byte(fmt.Sprintf(`{"schemaVersion":"ssc-init.ti-manifest.v1","family":"ti","version":"2026.08.14","sequence":42,"keyId":%q,"generatedAt":"2026-08-14T00:00:00Z","validFrom":"2026-08-13T23:00:00Z","validUntil":"2026-08-21T00:00:00Z","length":1234,"sha256":"%s","releaseTag":"ti-00000042","artifact":"ti-bundle.json"}`+"\n", keyID, strings.Repeat("a", 64)))
}

func manifestNow() time.Time { return time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC) }
