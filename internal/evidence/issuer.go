package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

// Anchor is the non-content identity captured while an issuer has verified a
// discovery result. It is retained only in the runtime-only target provenance.
type Anchor struct {
	Root         platform.FileFingerprint
	AssetRoot    platform.FileFingerprint
	RelativePath string
	Digest       string
	Size         int64
	Mode         uint32
	Fingerprint  platform.FileFingerprint
	MaxBytes     int64
}

// Issuer seals runtime-only evidence targets for a single discovery run.
// Its private nonce makes a provenance value unusable when any target field is
// changed after issuance.
type Issuer struct {
	nonce [sha256.Size]byte
}

type issuedTargetProof struct {
	issuer    *Issuer
	canonical [sha256.Size]byte
	seal      [sha256.Size]byte
	anchor    Anchor
}

// NewIssuer returns an issuer with a process-private cryptographic nonce.
func NewIssuer() *Issuer {
	issuer := &Issuer{}
	if _, err := io.ReadFull(rand.Reader, issuer.nonce[:]); err != nil {
		panic("secure random source unavailable")
	}
	return issuer
}

// Issue attaches a runtime-only provenance proof. No part of the proof has a
// JSON representation through LocalEvidenceTarget.
func (issuer *Issuer) Issue(target model.LocalEvidenceTarget, anchor Anchor) model.LocalEvidenceTarget {
	if issuer == nil {
		return target
	}
	canonical := canonicalTarget(target)
	proof := &issuedTargetProof{issuer: issuer, canonical: canonical, anchor: anchor}
	proof.seal = issuer.seal(canonical)
	target.Provenance = proof
	return target
}

func (issuer *Issuer) seal(canonical [sha256.Size]byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(issuer.nonce[:])
	_, _ = h.Write(canonical[:])
	var seal [sha256.Size]byte
	copy(seal[:], h.Sum(nil))
	return seal
}

// verifyIssuedTarget returns a detached anchor only when the complete target
// tuple is exactly the tuple which the owning issuer sealed.
func verifyIssuedTarget(target model.LocalEvidenceTarget) (Anchor, bool) {
	proof, ok := target.Provenance.(*issuedTargetProof)
	if !ok || proof == nil || proof.issuer == nil {
		return Anchor{}, false
	}
	canonical := canonicalTarget(target)
	if subtle.ConstantTimeCompare(canonical[:], proof.canonical[:]) != 1 {
		return Anchor{}, false
	}
	expected := proof.issuer.seal(canonical)
	if subtle.ConstantTimeCompare(expected[:], proof.seal[:]) != 1 {
		return Anchor{}, false
	}
	return proof.anchor, true
}

func canonicalTarget(target model.LocalEvidenceTarget) [sha256.Size]byte {
	h := sha256.New()
	for _, value := range []string{
		"ssc-init.local-evidence-target.v1",
		target.TargetID,
		target.AssetID,
		target.ObservationID,
		string(target.Kind),
		target.Subject,
		string(target.PresetStatus),
		target.RootPath,
		target.RelativePath,
	} {
		writeTargetField(h, []byte(value))
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func writeTargetField(w io.Writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}
