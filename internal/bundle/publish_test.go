package bundle

import (
	"crypto/ed25519"
	"testing"
)

func TestSignProducesDeterministicDetachedSignatureWithoutShippingAKey(t *testing.T) {
	publicKey, privateKey := deterministicKey(t, "publisher fixture")
	raw := validTIBundleBytes("publisher-key")
	first, err := Sign(raw, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Sign(raw, privateKey)
	if err != nil || string(first) != string(second) || !ed25519.Verify(publicKey, raw, first) {
		t.Fatalf("signature mismatch err=%v", err)
	}
}

func TestSignRejectsMalformedDocumentAndWrongPrivateKeySize(t *testing.T) {
	_, privateKey := deterministicKey(t, "publisher invalid fixture")
	if _, err := Sign([]byte(`{"schemaVersion":"other"}`), privateKey); err != ErrMalformed {
		t.Fatalf("malformed sign err=%v", err)
	}
	if _, err := Sign(validTIBundleBytes("publisher-key"), []byte("private")); err != ErrMalformed {
		t.Fatalf("short key sign err=%v", err)
	}
}
