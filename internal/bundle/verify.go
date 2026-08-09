package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"
)

var ErrVerification = errors.New("bundle verification failed")

type KeyRegistry map[Family]map[string]ed25519.PublicKey

type Verifier struct {
	Keys KeyRegistry
}

type Verified struct {
	Envelope Envelope
	Digest   [sha256.Size]byte
}

func (v Verifier) Verify(raw, signature []byte, now time.Time) (Verified, error) {
	envelope, err := Load(raw, now)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Verified{}, ErrVerification
	}
	publicKey := v.Keys[envelope.Family][envelope.KeyID]
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, raw, signature) {
		return Verified{}, ErrVerification
	}
	return Verified{Envelope: envelope, Digest: sha256.Sum256(raw)}, nil
}
