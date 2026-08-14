package bundle

import (
	"context"
	"encoding/hex"
	"os"
	"path"
	"strconv"
	"time"
)

type Freshness string

const (
	FreshnessMissing     Freshness = "missing"
	FreshnessFresh       Freshness = "fresh"
	FreshnessStale       Freshness = "stale"
	FreshnessExpired     Freshness = "expired"
	FreshnessUnavailable Freshness = "unavailable"
)

const staleGracePeriod = 7 * 24 * time.Hour

type Status struct {
	Family     Family    `json:"family"`
	Freshness  Freshness `json:"freshness"`
	Sequence   uint64    `json:"sequence,omitempty"`
	Version    string    `json:"version,omitempty"`
	ValidUntil time.Time `json:"validUntil,omitempty"`
	Digest     string    `json:"digest,omitempty"`
	KeyID      string    `json:"keyId,omitempty"`
	Records    int       `json:"records"`
	Malicious  int       `json:"malicious"`
	Vulnerable int       `json:"vulnerable"`
}

func (m Manager) Status(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	base := Status{Family: m.Family, Freshness: FreshnessMissing}
	info, err := os.Lstat(m.Layout.Root)
	if os.IsNotExist(err) {
		return base, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || m.Now == nil || !validFamily(m.Family) {
		base.Freshness = FreshnessUnavailable
		return base, nil
	}
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		base.Freshness = FreshnessUnavailable
		return base, nil
	}
	defer root.Close()
	current, err := readSequencePointer(root, "current")
	if err != nil {
		base.Freshness = FreshnessUnavailable
		return base, nil
	}
	versionPath := path.Join("versions", current)
	raw, rawErr := root.ReadFile(path.Join(versionPath, "bundle.json"))
	signature, signatureErr := root.ReadFile(path.Join(versionPath, "bundle.sig"))
	verified, verifyErr := m.Verifier.verifyStored(raw, signature)
	sequence, sequenceErr := strconv.ParseUint(current, 10, 64)
	if rawErr != nil || signatureErr != nil || verifyErr != nil || sequenceErr != nil || verified.Envelope.Sequence != sequence || verified.Envelope.Family != m.Family {
		base.Freshness = FreshnessUnavailable
		return base, nil
	}
	now := m.Now()
	freshness := FreshnessFresh
	if now.After(verified.Envelope.ValidUntil) {
		freshness = FreshnessStale
		if now.After(verified.Envelope.ValidUntil.Add(staleGracePeriod)) {
			freshness = FreshnessExpired
		}
	}
	status := Status{Family: m.Family, Freshness: freshness, Sequence: sequence, Version: verified.Envelope.Version, ValidUntil: verified.Envelope.ValidUntil, Digest: hex.EncodeToString(verified.Digest[:]), KeyID: verified.Envelope.KeyID}
	if verified.Envelope.TI != nil {
		status.Records = len(verified.Envelope.TI.Records)
		for _, record := range verified.Envelope.TI.Records {
			if record.Verdict == "known-malicious" {
				status.Malicious++
			} else {
				status.Vulnerable++
			}
		}
	}
	return status, nil
}
