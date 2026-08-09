package quarantine

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrUnsafeSource        = errors.New("quarantine source is unsafe")
	ErrIdentityChanged     = errors.New("quarantine source identity changed")
	ErrDigestMismatch      = errors.New("quarantine source digest mismatch")
	ErrQuarantineCollision = errors.New("quarantine destination exists")
	ErrQuarantineState     = errors.New("quarantine state update failed")
)

const maxQuarantineBytes = 512 << 20

type Recorder interface {
	SaveQuarantineRecord(context.Context, Record) error
}

type Manager struct {
	Home     string
	Recorder Recorder
	Now      func() time.Time

	beforeSourceRemoval func()
}

func (m Manager) Quarantine(ctx context.Context, record Record) (Record, error) {
	now := time.Now().UTC
	if m.Now != nil {
		now = func() time.Time { return m.Now().UTC() }
	}
	record.State, record.FailureCode, record.RequestedAt, record.QuarantinedAt, record.RestoredAt = StateRequested, "", now(), time.Time{}, time.Time{}
	if m.Recorder == nil || !record.Valid() || !strings.HasPrefix(record.OriginalRef, "$HOME/") {
		return Record{}, ErrUnsafeSource
	}
	if err := m.Recorder.SaveQuarantineRecord(ctx, record); err != nil {
		return Record{}, ErrQuarantineState
	}
	fail := func(code FailureCode, cause error) (Record, error) {
		failed := record
		failed.State, failed.FailureCode = StateFailed, code
		if err := m.Recorder.SaveQuarantineRecord(context.WithoutCancel(ctx), failed); err != nil {
			return Record{}, ErrQuarantineState
		}
		return failed, cause
	}
	if err := ctx.Err(); err != nil {
		return fail(FailureCancelled, err)
	}

	homeRoot, err := openVerifiedAbsoluteRoot(m.Home)
	if err != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	defer homeRoot.Close()
	relative := strings.TrimPrefix(record.OriginalRef, "$HOME/")
	components := strings.Split(relative, "/")
	if len(components) == 0 {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	sourceParent, err := openVerifiedPath(ctx, homeRoot, components[:len(components)-1], false)
	if err != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	if sourceParent != homeRoot {
		defer sourceParent.Close()
	}
	basename := components[len(components)-1]
	expected, err := sourceParent.Lstat(basename)
	if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.Mode().IsRegular() || uint32(expected.Mode().Perm()) != record.OriginalMode {
		return fail(FailureIdentityChanged, ErrUnsafeSource)
	}
	source, err := sourceParent.OpenFile(basename, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(expected, opened) || !opened.Mode().IsRegular() || opened.Size() > maxQuarantineBytes {
		return fail(FailureIdentityChanged, ErrUnsafeSource)
	}

	quarantineRoot, err := openVerifiedPath(ctx, homeRoot, []string{"Library", "Application Support", "SSC Init", "quarantine"}, true)
	if err != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	defer quarantineRoot.Close()
	quarantineInfo, err := quarantineRoot.Lstat(".")
	if err != nil || quarantineInfo.Mode().Perm()&0o077 != 0 {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	if err := ensurePrivateDirectory(quarantineRoot, "files"); err != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	filesRoot, err := openVerifiedPath(ctx, quarantineRoot, []string{"files"}, false)
	if err != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	defer filesRoot.Close()
	name := quarantineFileName(record.ID)
	destination, err := filesRoot.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fail(FailureCollision, ErrQuarantineCollision)
		}
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	created := true
	defer func() {
		_ = destination.Close()
		if created {
			_ = filesRoot.Remove(name)
		}
	}()
	hasher := sha256.New()
	if _, err := copyQuarantine(ctx, io.MultiWriter(destination, hasher), source); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fail(FailureCancelled, err)
		}
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(record.SHA256)) != 1 {
		return fail(FailureVerificationFailed, ErrDigestMismatch)
	}
	if err := destination.Chmod(0o600); err != nil || destination.Sync() != nil {
		return fail(FailureUnavailable, ErrUnsafeSource)
	}
	record.State, record.QuarantinedAt = StateQuarantined, now()
	if err := m.Recorder.SaveQuarantineRecord(context.WithoutCancel(ctx), record); err != nil {
		return Record{}, ErrQuarantineState
	}
	created = false
	if m.beforeSourceRemoval != nil {
		m.beforeSourceRemoval()
	}
	current, err := sourceParent.Lstat(basename)
	if err != nil || !os.SameFile(expected, current) {
		return record, ErrIdentityChanged
	}
	if err := sourceParent.Remove(basename); err != nil {
		return record, ErrIdentityChanged
	}
	return record, nil
}

func (m Manager) Restore(ctx context.Context, record Record) (Record, error) {
	if m.Recorder == nil || !record.Valid() || record.State != StateQuarantined || !strings.HasPrefix(record.OriginalRef, "$HOME/") {
		return Record{}, ErrQuarantineState
	}
	if err := ctx.Err(); err != nil {
		return record, err
	}
	homeRoot, err := openVerifiedAbsoluteRoot(m.Home)
	if err != nil {
		return record, ErrUnsafeSource
	}
	defer homeRoot.Close()
	relative := strings.TrimPrefix(record.OriginalRef, "$HOME/")
	components := strings.Split(relative, "/")
	parent, err := openVerifiedPath(ctx, homeRoot, components[:len(components)-1], false)
	if err != nil {
		return record, ErrUnsafeSource
	}
	if parent != homeRoot {
		defer parent.Close()
	}
	basename := components[len(components)-1]
	if _, err := parent.Lstat(basename); !errors.Is(err, fs.ErrNotExist) {
		return record, ErrQuarantineCollision
	}
	quarantineRoot, err := openVerifiedPath(ctx, homeRoot, []string{"Library", "Application Support", "SSC Init", "quarantine", "files"}, false)
	if err != nil {
		return record, ErrUnsafeSource
	}
	defer quarantineRoot.Close()
	name := quarantineFileName(record.ID)
	expected, err := quarantineRoot.Lstat(name)
	if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.Mode().IsRegular() || expected.Mode().Perm() != 0o600 {
		return record, ErrUnsafeSource
	}
	source, err := quarantineRoot.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return record, ErrUnsafeSource
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(expected, opened) || opened.Size() > maxQuarantineBytes {
		return record, ErrIdentityChanged
	}
	destination, err := parent.OpenFile(basename, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return record, ErrQuarantineCollision
		}
		return record, ErrUnsafeSource
	}
	keepDestination := false
	defer func() {
		_ = destination.Close()
		if !keepDestination {
			_ = parent.Remove(basename)
		}
	}()
	hasher := sha256.New()
	if _, err := copyQuarantine(ctx, io.MultiWriter(destination, hasher), source); err != nil {
		return record, err
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(record.SHA256)) != 1 {
		return record, ErrDigestMismatch
	}
	if err := destination.Chmod(fs.FileMode(record.OriginalMode)); err != nil || destination.Sync() != nil {
		return record, ErrUnsafeSource
	}
	current, err := quarantineRoot.Lstat(name)
	if err != nil || !os.SameFile(expected, current) {
		return record, ErrIdentityChanged
	}
	restored := record
	restored.State, restored.RestoredAt = StateRestored, time.Now().UTC()
	if m.Now != nil {
		restored.RestoredAt = m.Now().UTC()
	}
	if err := m.Recorder.SaveQuarantineRecord(context.WithoutCancel(ctx), restored); err != nil {
		return record, ErrQuarantineState
	}
	keepDestination = true
	_ = quarantineRoot.Remove(name)
	return restored, nil
}

func (m Manager) quarantineFile(id string) string {
	return path.Join(m.Home, "Library", "Application Support", "SSC Init", "quarantine", "files", quarantineFileName(id))
}

func quarantineFileName(id string) string {
	digest := sha256.Sum256([]byte("ssc-init.quarantine.file.v1\x00" + id))
	return fmt.Sprintf("%x", digest)
}

func openVerifiedAbsoluteRoot(name string) (*os.Root, error) {
	expected, err := os.Lstat(name)
	if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
		return nil, ErrUnsafeSource
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, ErrUnsafeSource
	}
	opened, err := root.Lstat(".")
	if err != nil || !os.SameFile(expected, opened) {
		root.Close()
		return nil, ErrUnsafeSource
	}
	return root, nil
}

func openVerifiedPath(ctx context.Context, initial *os.Root, components []string, create bool) (*os.Root, error) {
	current := initial
	owned := false
	for _, component := range components {
		if err := ctx.Err(); err != nil || component == "" || component == "." || component == ".." || strings.Contains(component, "/") {
			if owned {
				current.Close()
			}
			if err != nil {
				return nil, err
			}
			return nil, ErrUnsafeSource
		}
		expected, err := current.Lstat(component)
		if errors.Is(err, fs.ErrNotExist) && create {
			if err = current.Mkdir(component, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				if owned {
					current.Close()
				}
				return nil, err
			}
			expected, err = current.Lstat(component)
		}
		if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
			if owned {
				current.Close()
			}
			return nil, ErrUnsafeSource
		}
		child, err := current.OpenRoot(component)
		if err != nil {
			if owned {
				current.Close()
			}
			return nil, err
		}
		opened, err := child.Lstat(".")
		if err != nil || !os.SameFile(expected, opened) {
			child.Close()
			if owned {
				current.Close()
			}
			return nil, ErrUnsafeSource
		}
		if owned {
			current.Close()
		}
		current, owned = child, true
	}
	return current, nil
}

func ensurePrivateDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		if err = root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err = root.Lstat(name)
	}
	return func() error {
		if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return ErrUnsafeSource
		}
		return nil
	}()
}

func copyQuarantine(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 256<<10)
	defer clear(buffer)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if total+int64(read) > maxQuarantineBytes {
				return total, ErrUnsafeSource
			}
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil || written != read {
				return total, ErrUnsafeSource
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, ErrUnsafeSource
		}
	}
}
