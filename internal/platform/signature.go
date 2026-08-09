package platform

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const codesignPath = "/usr/bin/codesign"

// ExecutableIdentityVerifier rechecks the descriptor-anchored executable
// identity before and after an external inspection.
type ExecutableIdentityVerifier interface {
	Verify(ExecutableEvidence) error
}

// SignatureInspector returns a closed platform-signature fact. Diagnostics
// from the platform tool are never returned or persisted.
type SignatureInspector interface {
	Inspect(context.Context, ExecutableEvidence, ExecutableIdentityVerifier) (model.Signature, error)
}

type boundedSignatureInspector struct {
	goos   string
	runner Runner
}

// NewSignatureInspector constructs the host inspector around a bounded runner.
func NewSignatureInspector(runner Runner) SignatureInspector {
	return newSignatureInspector(runtime.GOOS, runner)
}

func newSignatureInspector(goos string, runner Runner) SignatureInspector {
	return &boundedSignatureInspector{goos: goos, runner: runner}
}

func (i *boundedSignatureInspector) Inspect(ctx context.Context, executable ExecutableEvidence, verifier ExecutableIdentityVerifier) (model.Signature, error) {
	if i.goos != "darwin" {
		return model.Signature{Status: model.SignatureUnsupported}, nil
	}
	unavailable := model.Signature{Status: model.SignatureUnavailable}
	if err := ctx.Err(); err != nil {
		return unavailable, err
	}
	if i.runner == nil || verifier == nil || !filepath.IsAbs(executable.Path) {
		return unavailable, errors.New("signature inspection is unavailable")
	}
	if err := verifier.Verify(executable); err != nil {
		return unavailable, fmt.Errorf("verify executable before signature inspection: %w", err)
	}

	verification, runErr := i.runner.Run(ctx, codesignPath, "--verify", "--strict", "--verbose=2", executable.Path)
	if err := ctx.Err(); err != nil {
		return unavailable, err
	}
	if verification.Truncated {
		return unavailable, errors.New("signature verification output exceeded bound")
	}
	if verification.ExitCode != 0 {
		if err := verifier.Verify(executable); err != nil {
			return unavailable, fmt.Errorf("verify executable after signature inspection: %w", err)
		}
		if verification.ExitCode < 0 {
			return unavailable, errors.New("signature verification did not complete")
		}
		if strings.Contains(strings.ToLower(verification.Stderr), "code object is not signed at all") {
			return model.Signature{Status: model.SignatureUnsigned}, nil
		}
		return model.Signature{Status: model.SignatureInvalid}, nil
	}
	if runErr != nil {
		return unavailable, errors.New("signature verification failed")
	}

	details, err := i.runner.Run(ctx, codesignPath, "--display", "--verbose=4", executable.Path)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return unavailable, ctxErr
	}
	if err != nil || details.ExitCode != 0 || details.Truncated {
		return unavailable, errors.New("signature identity inspection failed")
	}
	identifier, teamID, ok := parseCodesignIdentity(details.Stderr)
	if !ok {
		return unavailable, errors.New("signature identity is unavailable")
	}
	if err := verifier.Verify(executable); err != nil {
		return unavailable, fmt.Errorf("verify executable after signature inspection: %w", err)
	}
	return model.Signature{Status: model.SignatureValid, Identifier: identifier, TeamID: teamID}, nil
}

func parseCodesignIdentity(stderr string) (string, string, bool) {
	var identifier, teamID string
	for _, line := range strings.Split(stderr, "\n") {
		switch {
		case strings.HasPrefix(line, "Identifier="):
			identifier = strings.TrimPrefix(line, "Identifier=")
		case strings.HasPrefix(line, "TeamIdentifier="):
			teamID = strings.TrimPrefix(line, "TeamIdentifier=")
		}
	}
	return identifier, teamID, signatureToken(identifier, 255, false) && len(teamID) == 10 && signatureToken(teamID, 10, true)
}

func signatureToken(value string, maximum int, uppercaseOnly bool) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		allowed := character >= '0' && character <= '9' || character >= 'A' && character <= 'Z'
		if !uppercaseOnly {
			allowed = allowed || character >= 'a' && character <= 'z' || character == '.' || character == '_' || character == '-'
		}
		if !allowed {
			return false
		}
	}
	return true
}
