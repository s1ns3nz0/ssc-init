package bundle

import "crypto/ed25519"

// Sign validates a complete closed bundle document and returns a detached
// Ed25519 signature over its exact bytes. Private keys are caller-owned and
// are never loaded, generated, or persisted by this package.
func Sign(raw []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrMalformed
	}
	if _, err := loadEnvelope(raw, nil); err != nil {
		return nil, ErrMalformed
	}
	return ed25519.Sign(privateKey, raw), nil
}

func FamilyOf(raw []byte) (Family, error) {
	envelope, err := loadEnvelope(raw, nil)
	if err != nil {
		return "", ErrMalformed
	}
	return envelope.Family, nil
}
