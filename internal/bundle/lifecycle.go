package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	ErrInstall  = errors.New("bundle installation failed")
	ErrRollback = errors.New("bundle rollback was refused")
)

type Manager struct {
	Layout   Layout
	Family   Family
	Verifier Verifier
	Now      func() time.Time
}

func (m Manager) Install(ctx context.Context, bundlePath, signaturePath string) (Verified, error) {
	if err := ctx.Err(); err != nil {
		return Verified{}, err
	}
	if !filepath.IsAbs(bundlePath) || !filepath.IsAbs(signaturePath) || m.Now == nil || !validFamily(m.Family) {
		return Verified{}, ErrInstall
	}
	raw, err := readRegularBounded(bundlePath, maxBundleBytes)
	if err != nil {
		return Verified{}, ErrInstall
	}
	signature, err := readRegularBounded(signaturePath, 1024)
	if err != nil {
		return Verified{}, ErrInstall
	}
	verified, err := m.Verifier.Verify(raw, signature, m.Now())
	if err != nil || verified.Envelope.Family != m.Family {
		return Verified{}, ErrInstall
	}
	if err := ctx.Err(); err != nil {
		return Verified{}, err
	}
	if err := m.Layout.Initialize(); err != nil {
		return Verified{}, ErrInstall
	}
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		return Verified{}, ErrInstall
	}
	defer root.Close()
	sequence := strconv.FormatUint(verified.Envelope.Sequence, 10)
	if highWater, highWaterErr := readSequencePointer(root, "highest-sequence"); highWaterErr == nil {
		highest, _ := strconv.ParseUint(highWater, 10, 64)
		if verified.Envelope.Sequence < highest {
			return Verified{}, ErrRollback
		}
		if verified.Envelope.Sequence == highest {
			acceptedPath := path.Join("versions", sequence)
			acceptedRaw, rawErr := root.ReadFile(path.Join(acceptedPath, "bundle.json"))
			acceptedSignature, signatureErr := root.ReadFile(path.Join(acceptedPath, "bundle.sig"))
			accepted, verifyErr := m.Verifier.Verify(acceptedRaw, acceptedSignature, m.Now())
			if rawErr != nil || signatureErr != nil || verifyErr != nil || accepted.Digest != verified.Digest {
				return Verified{}, ErrRollback
			}
		}
	}
	staging := path.Join("staging", sequence)
	installed := path.Join("versions", sequence)
	if err := root.RemoveAll(staging); err != nil || root.MkdirAll(staging, 0o700) != nil {
		return Verified{}, ErrInstall
	}
	discard := func(result error) (Verified, error) {
		_ = root.RemoveAll(staging)
		return Verified{}, result
	}
	if err := writeStagedFile(root, path.Join(staging, "bundle.json"), raw); err != nil {
		return discard(ErrInstall)
	}
	if err := writeStagedFile(root, path.Join(staging, "bundle.sig"), signature); err != nil {
		return discard(ErrInstall)
	}
	stagedRaw, rawErr := root.ReadFile(path.Join(staging, "bundle.json"))
	stagedSignature, signatureErr := root.ReadFile(path.Join(staging, "bundle.sig"))
	staged, verifyErr := m.Verifier.Verify(stagedRaw, stagedSignature, m.Now())
	if rawErr != nil || signatureErr != nil || verifyErr != nil || staged.Digest != verified.Digest {
		return discard(ErrInstall)
	}
	if err := ctx.Err(); err != nil {
		return discard(err)
	}
	if err := root.RemoveAll(installed); err != nil || root.Rename(staging, installed) != nil {
		return discard(ErrInstall)
	}
	if err := writeSequencePointer(root, "highest-sequence", sequence); err != nil {
		return Verified{}, ErrInstall
	}
	current, currentErr := readSequencePointer(root, "current")
	if currentErr == nil && current != sequence {
		if err := writeSequencePointer(root, "previous", current); err != nil {
			return Verified{}, ErrInstall
		}
	}
	if err := writeSequencePointer(root, "current", sequence); err != nil {
		return Verified{}, ErrInstall
	}
	return staged, nil
}

func (m Manager) Rollback(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.Now == nil || !validFamily(m.Family) || m.Layout.Initialize() != nil {
		return ErrRollback
	}
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		return ErrRollback
	}
	defer root.Close()
	current, currentErr := readSequencePointer(root, "current")
	previous, previousErr := readSequencePointer(root, "previous")
	if currentErr != nil || previousErr != nil || current == previous {
		return ErrRollback
	}
	previousPath := path.Join("versions", previous)
	raw, rawErr := root.ReadFile(path.Join(previousPath, "bundle.json"))
	signature, signatureErr := root.ReadFile(path.Join(previousPath, "bundle.sig"))
	verified, verifyErr := m.Verifier.Verify(raw, signature, m.Now())
	if rawErr != nil || signatureErr != nil || verifyErr != nil || strconv.FormatUint(verified.Envelope.Sequence, 10) != previous || verified.Envelope.Family != m.Family {
		return ErrRollback
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if writeSequencePointer(root, "previous", current) != nil || writeSequencePointer(root, "current", previous) != nil {
		return ErrRollback
	}
	return nil
}

func readRegularBounded(filePath string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInstall
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrInstall
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func writeStagedFile(root *os.Root, name string, contents []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	return file.Sync()
}

func readSequencePointer(root *os.Root, name string) (string, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32 {
		return "", ErrInstall
	}
	raw, err := root.ReadFile(name)
	value := strings.TrimSpace(string(raw))
	sequence, parseErr := strconv.ParseUint(value, 10, 64)
	if err != nil || parseErr != nil || sequence == 0 || value != fmt.Sprintf("%d", sequence) {
		return "", ErrInstall
	}
	return value, nil
}

func writeSequencePointer(root *os.Root, name, sequence string) error {
	temporary := name + ".tmp"
	if err := root.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return ErrInstall
	}
	if err := writeStagedFile(root, temporary, []byte(sequence+"\n")); err != nil {
		return ErrInstall
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return ErrInstall
	}
	return nil
}
