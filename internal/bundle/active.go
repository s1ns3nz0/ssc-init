package bundle

import (
	"context"
	"errors"
	"os"
	"path"
	"strconv"
)

var ErrActiveUnavailable = errors.New("active bundle is unavailable")

type ActiveBundle struct {
	Verified Verified
	Status   Status
}

func (m Manager) Active(ctx context.Context) (ActiveBundle, error) {
	status, err := m.Status(ctx)
	if err != nil {
		return ActiveBundle{}, err
	}
	if status.Freshness == FreshnessMissing || status.Freshness == FreshnessUnavailable || status.Sequence == 0 {
		return ActiveBundle{}, ErrActiveUnavailable
	}
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		return ActiveBundle{}, ErrActiveUnavailable
	}
	defer root.Close()
	sequence := strconv.FormatUint(status.Sequence, 10)
	versionPath := path.Join("versions", sequence)
	raw, rawErr := root.ReadFile(path.Join(versionPath, "bundle.json"))
	signature, signatureErr := root.ReadFile(path.Join(versionPath, "bundle.sig"))
	verified, verifyErr := m.Verifier.verifyStored(raw, signature)
	if rawErr != nil || signatureErr != nil || verifyErr != nil || verified.Envelope.Family != m.Family || verified.Envelope.Sequence != status.Sequence {
		return ActiveBundle{}, ErrActiveUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ActiveBundle{}, err
	}
	return ActiveBundle{Verified: verified, Status: status}, nil
}
