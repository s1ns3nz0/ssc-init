package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestVerifierAcceptsExactBytesWithFamilyScopedKey(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "ti fixture key")
	raw := validTIBundleBytes("ti-key")
	signature := ed25519.Sign(privateKey, raw)
	verified, err := (Verifier{Keys: KeyRegistry{FamilyTI: {"ti-key": publicKey}}}).Verify(raw, signature, testBundleNow())
	wantDigest := sha256.Sum256(raw)
	if err != nil || verified.Envelope.Family != FamilyTI || verified.Digest != wantDigest {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
}

func TestVerifierRejectsTamperUnknownAndWrongFamilyWithoutEcho(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "shared fixture key")
	raw := validTIBundleBytes("private-key-id")
	signature := ed25519.Sign(privateKey, raw)
	for _, verifier := range []Verifier{
		{Keys: KeyRegistry{FamilyTI: {"private-key-id": publicKey}}},
		{Keys: KeyRegistry{FamilyTI: {"other": publicKey}}},
		{Keys: KeyRegistry{FamilyPolicy: {"private-key-id": publicKey}}},
	} {
		candidate := append([]byte(nil), raw...)
		if _, ok := verifier.Keys[FamilyTI]["private-key-id"]; ok {
			candidate[len(candidate)-2] ^= 1
		}
		if _, err := verifier.Verify(candidate, signature, testBundleNow()); err != ErrVerification || strings.Contains(err.Error(), "private-key-id") {
			t.Fatalf("verification accepted or echoed key: err=%v", err)
		}
	}
}

func deterministicKey(t *testing.T, label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func validTIBundleBytes(keyID string) []byte {
	return []byte(`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","version":"2026.08.10","sequence":7,"keyId":"` + keyID + `","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"records":[]}}`)
}

func testBundleNow() time.Time { return time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC) }
