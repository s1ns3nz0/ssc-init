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
	Root              platform.FileFingerprint
	AssetRoot         platform.FileFingerprint
	AssetRelativePath string
	RelativePath      string
	Digest            string
	Size              int64
	Mode              uint32
	Fingerprint       platform.FileFingerprint
	MaxBytes          int64
}

// Issuer seals runtime-only evidence targets for a single discovery run.
// Its private nonce makes a provenance value unusable when any target field is
// changed after issuance.
type Issuer struct {
	nonce  [sha256.Size]byte
	active bool
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
	issuer.active = true
	return issuer
}

// Issue attaches a runtime-only provenance proof. No part of the proof has a
// JSON representation through LocalEvidenceTarget.
func (issuer *Issuer) Issue(target model.LocalEvidenceTarget, anchor Anchor) model.LocalEvidenceTarget {
	if issuer == nil || !issuer.active {
		return target
	}
	canonical := canonicalIssuedTarget(target, anchor)
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
func verifyIssuedTarget(target model.LocalEvidenceTarget, expected *Issuer) (Anchor, *issuedTargetProof, bool) {
	proof, ok := target.Provenance.(*issuedTargetProof)
	if !ok || proof == nil || proof.issuer == nil || expected == nil || !expected.active || !proof.issuer.active || proof.issuer != expected {
		return Anchor{}, proof, false
	}
	canonical := canonicalIssuedTarget(target, proof.anchor)
	if subtle.ConstantTimeCompare(canonical[:], proof.canonical[:]) != 1 {
		return Anchor{}, proof, false
	}
	expectedSeal := proof.issuer.seal(canonical)
	if subtle.ConstantTimeCompare(expectedSeal[:], proof.seal[:]) != 1 {
		return Anchor{}, proof, false
	}
	return proof.anchor, proof, true
}

func canonicalIssuedTarget(target model.LocalEvidenceTarget, anchor Anchor) [sha256.Size]byte {
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
	writeFingerprint(h, anchor.Root)
	writeFingerprint(h, anchor.AssetRoot)
	for _, value := range []string{anchor.AssetRelativePath, anchor.RelativePath, anchor.Digest} {
		writeTargetField(h, []byte(value))
	}
	writeInt64(h, anchor.Size)
	writeUint32(h, anchor.Mode)
	writeFingerprint(h, anchor.Fingerprint)
	writeInt64(h, anchor.MaxBytes)
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func writeFingerprint(w io.Writer, value platform.FileFingerprint) {
	writeUint64(w, value.Device)
	writeUint64(w, value.Inode)
	writeUint32(w, value.Mode)
	writeInt64(w, value.Size)
	writeInt64(w, value.ModTimeNS)
	writeInt64(w, value.ChangeTimeNS)
}

func writeUint64(w io.Writer, value uint64) {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	writeTargetField(w, buffer[:])
}

func writeInt64(w io.Writer, value int64) { writeUint64(w, uint64(value)) }

func writeUint32(w io.Writer, value uint32) {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], value)
	writeTargetField(w, buffer[:])
}

func (issuer *Issuer) clearRuntime() {
	if issuer != nil {
		clear(issuer.nonce[:])
		issuer.active = false
	}
}

func (proof *issuedTargetProof) clearRuntime() {
	if proof == nil {
		return
	}
	proof.issuer = nil
	clear(proof.canonical[:])
	clear(proof.seal[:])
	proof.anchor = Anchor{}
}

func writeTargetField(w io.Writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}
