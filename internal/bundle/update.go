package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type UpdateStatus string

const (
	UpdateUpdated     UpdateStatus = "updated"
	UpdateCurrent     UpdateStatus = "current"
	UpdateDegraded    UpdateStatus = "degraded"
	UpdateUnavailable UpdateStatus = "unavailable"
)

type UpdateErrorCode string

const (
	UpdateErrorNone             UpdateErrorCode = ""
	UpdateErrorNetwork          UpdateErrorCode = "network-unavailable"
	UpdateErrorRedirectRejected UpdateErrorCode = "redirect-rejected"
	UpdateErrorResponseLimit    UpdateErrorCode = "response-limit"
	UpdateErrorManifestInvalid  UpdateErrorCode = "manifest-invalid"
	UpdateErrorSignatureInvalid UpdateErrorCode = "signature-invalid"
	UpdateErrorBundleInvalid    UpdateErrorCode = "bundle-invalid"
	UpdateErrorRollbackRejected UpdateErrorCode = "rollback-rejected"
	UpdateErrorActivationFailed UpdateErrorCode = "activation-failed"
	UpdateErrorCancellation     UpdateErrorCode = "cancellation"
)

type UpdateResult struct {
	Status     UpdateStatus    `json:"status"`
	ErrorCode  UpdateErrorCode `json:"errorCode,omitempty"`
	Sequence   uint64          `json:"sequence,omitempty"`
	Digest     string          `json:"digest,omitempty"`
	KeyID      string          `json:"keyId,omitempty"`
	Freshness  Freshness       `json:"freshness"`
	Records    int             `json:"records"`
	Malicious  int             `json:"malicious"`
	Vulnerable int             `json:"vulnerable"`
}

type Updater struct {
	Manager *Manager
	Client  *http.Client
	Base    *url.URL
	Keys    KeyRegistry
	Now     func() time.Time
}

func (u Updater) Update(ctx context.Context) UpdateResult {
	if err := ctx.Err(); err != nil {
		return u.failed(ctx, UpdateErrorCancellation)
	}
	if u.Manager == nil || u.Client == nil || u.Now == nil || !validUpdateBase(u.Base) {
		return u.failed(ctx, UpdateErrorNetwork)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	manifestRaw, code := u.fetch(ctx, latestPath("ti-manifest.json"), maxManifestBytes, "ti-manifest.json")
	if code != UpdateErrorNone {
		return u.failed(ctx, code)
	}
	manifestSig, code := u.fetch(ctx, latestPath("ti-manifest.sig"), 1024, "ti-manifest.sig")
	if code != UpdateErrorNone {
		return u.failed(ctx, code)
	}
	now := u.Now()
	manifest, err := LoadManifest(manifestRaw, now)
	if err != nil {
		return u.failed(ctx, UpdateErrorManifestInvalid)
	}
	verifiedManifest, err := VerifyManifest(manifestRaw, manifestSig, u.Keys, now)
	if err != nil {
		return u.failed(ctx, UpdateErrorSignatureInvalid)
	}

	local, _ := u.Manager.Status(ctx)
	if local.Sequence > manifest.Sequence {
		return u.failed(ctx, UpdateErrorRollbackRejected)
	}
	if local.Sequence == manifest.Sequence {
		if local.Digest == manifest.SHA256 {
			return resultFromStatus(UpdateCurrent, UpdateErrorNone, local)
		}
		return u.failed(ctx, UpdateErrorRollbackRejected)
	}

	bundlePath := releasePath(manifest.ReleaseTag, manifest.Artifact)
	directory, err := os.MkdirTemp("", "ssc-init-ti-update-")
	if err != nil {
		return u.failed(ctx, UpdateErrorActivationFailed)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return u.failed(ctx, UpdateErrorActivationFailed)
	}
	bundleFile, signatureFile := filepath.Join(directory, "bundle.json"), filepath.Join(directory, "bundle.sig")
	written, digest, code := u.fetchFile(ctx, bundlePath, manifest.Length, manifest.Artifact, bundleFile)
	if code != UpdateErrorNone {
		return u.failed(ctx, code)
	}
	if written != manifest.Length {
		return u.failed(ctx, UpdateErrorBundleInvalid)
	}
	if hex.EncodeToString(digest[:]) != manifest.SHA256 {
		return u.failed(ctx, UpdateErrorBundleInvalid)
	}
	signature, code := u.fetch(ctx, releasePath(manifest.ReleaseTag, "ti-bundle.sig"), 1024, "ti-bundle.sig")
	if code != UpdateErrorNone {
		return u.failed(ctx, code)
	}
	if len(signature) != ed25519.SignatureSize {
		return u.failed(ctx, UpdateErrorSignatureInvalid)
	}
	bundleRaw, err := readRegularBounded(bundleFile, maxBundleBytes)
	if err != nil {
		return u.failed(ctx, UpdateErrorBundleInvalid)
	}
	preverified, err := u.Manager.Verifier.Verify(bundleRaw, signature, now)
	if err != nil {
		return u.failed(ctx, UpdateErrorSignatureInvalid)
	}
	if preverified.Digest != digest || preverified.Envelope.Family != FamilyTI ||
		preverified.Envelope.Sequence != manifest.Sequence || preverified.Envelope.Version != manifest.Version ||
		preverified.Envelope.KeyID != manifest.KeyID || !preverified.Envelope.GeneratedAt.Equal(manifest.GeneratedAt) ||
		!preverified.Envelope.ValidFrom.Equal(manifest.ValidFrom) || !preverified.Envelope.ValidUntil.Equal(manifest.ValidUntil) {
		return u.failed(ctx, UpdateErrorBundleInvalid)
	}

	if os.WriteFile(signatureFile, signature, 0o600) != nil {
		return u.failed(ctx, UpdateErrorActivationFailed)
	}
	installed, err := u.Manager.Install(ctx, bundleFile, signatureFile)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return u.failed(ctx, UpdateErrorCancellation)
		}
		if errors.Is(err, ErrRollback) {
			return u.failed(ctx, UpdateErrorRollbackRejected)
		}
		return u.failed(ctx, UpdateErrorActivationFailed)
	}
	if installed.Envelope.Sequence != verifiedManifest.Manifest.Sequence || installed.Digest != digest {
		return u.failed(ctx, UpdateErrorActivationFailed)
	}
	status, _ := u.Manager.Status(ctx)
	return resultFromStatus(UpdateUpdated, UpdateErrorNone, status)
}

func (u Updater) failed(ctx context.Context, code UpdateErrorCode) UpdateResult {
	if ctx.Err() != nil {
		code = UpdateErrorCancellation
	}
	status := Status{Family: FamilyTI, Freshness: FreshnessMissing}
	if u.Manager != nil {
		statusCtx := context.WithoutCancel(ctx)
		if current, err := u.Manager.Status(statusCtx); err == nil {
			status = current
		}
	}
	resultStatus := UpdateUnavailable
	if status.Freshness == FreshnessFresh || status.Freshness == FreshnessStale {
		resultStatus = UpdateDegraded
	}
	return resultFromStatus(resultStatus, code, status)
}

func resultFromStatus(state UpdateStatus, code UpdateErrorCode, status Status) UpdateResult {
	return UpdateResult{Status: state, ErrorCode: code, Sequence: status.Sequence, Digest: status.Digest, KeyID: status.KeyID, Freshness: status.Freshness, Records: status.Records, Malicious: status.Malicious, Vulnerable: status.Vulnerable}
}
