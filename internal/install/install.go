// Package install performs staged, digest-verified core installations under
// the shared SSC Init data directory (design §5.3, §11). It never reads,
// writes, or removes the state database, intelligence bundles, reports, or
// quarantine.
//
// The core is never downloaded here: an adapter obtains the release artifact
// and its published SHA-256, and this package verifies what it was handed.
// Every install-side path is resolved through an os.Root opened on the install
// root, so no supplied name can escape it. The one absolute path rebuilt after
// that root is verified is the core binary handed to the health check, because
// a descriptor cannot be executed; it is assembled only from validated version
// names and the version is re-verified through the root afterwards. Errors are
// value-free: they carry no path, no digest, and no version.
package install

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

// maxCoreSize bounds what an adapter-supplied path may spend of the user's
// disk. A universal ssc-init binary is two figures of megabytes.
const maxCoreSize = 512 << 20

// manifestSchema names the version-and-digest record written beside a staged
// core. Nothing else is recorded: no source path, no time, no host.
const manifestSchema = "ssc-init.install.manifest.v1"

var (
	errUnsupportedVersion = errors.New("unsupported core version")
	errUnusableDigest     = errors.New("expected core digest is not a sha-256 digest")
	errInstallRoot        = errors.New("install root is unavailable")
	errStagingRoot        = errors.New("staging directory is unavailable")
	errSourceUnreadable   = errors.New("core binary source cannot be read")
	errSourceNotRegular   = errors.New("core binary source is not a regular file")
	errSourceTooLarge     = errors.New("core binary source exceeds the install size limit")
	errStagedWrite        = errors.New("staged core cannot be written")
	errDigestMismatch     = errors.New("core binary digest does not match the expected digest")
	errNotUniversal       = errors.New("core binary is not a macos universal executable")
	errMissingSlice       = errors.New("core binary does not provide both required architectures")
	errPromote            = errors.New("verified core cannot be promoted")
	errNotInstalled       = errors.New("requested core version is not installed")
	errManifest           = errors.New("installed core has no usable install manifest")
	errNoHealthCheck      = errors.New("no health check is configured for this installation")
	errHealthCheck        = errors.New("staged core failed its health check")
	errNothingActive      = errors.New("no core version is active")
	errUnusablePointer    = errors.New("current-version pointer is unusable")
	errNoPrevious         = errors.New("no previous known-good core version is available")
	errPointerWrite       = errors.New("current-version pointer cannot be written")
	errPrune              = errors.New("superseded core versions cannot be removed")
	errInstallBusy        = errors.New("another installation is already in progress")
)

// Pointer file names, relative to the install root. Each is written to a
// sibling temporary and renamed into place, so a reader sees either the old
// version or the new one and never a half-written name.
const (
	currentPointer  = "current"
	previousPointer = "previous"
	pointerSuffix   = ".tmp"
	lockFile        = ".lock"
	// maxPointerSize bounds what a pointer read will accept before it is even
	// parsed: a pointer holds one short version string and a newline.
	maxPointerSize = 128
	// maxManifestSize bounds the version-and-digest record written by Stage.
	maxManifestSize = 4096
)

// Manager owns one shared installation.
type Manager struct {
	Home   string
	Layout platform.InstallLayout

	// Health decides whether a staged version may become active (design §11:
	// stage, verify, health check, atomic switch, rollback). It receives the
	// path of the core binary that was just verified against its recorded
	// digest, and the production wiring runs that binary's `doctor --json`.
	//
	// Executing it does not weaken the "default scans execute no process"
	// invariant: the executable is not a discovered asset but the tool this
	// package copied and hashed itself, it runs only on an explicit install or
	// rollback, and no scan path reaches here. Activate refuses to switch when
	// Health is nil, so an unchecked version can never become active.
	Health func(ctx context.Context, executablePath string) error
}

// New returns the manager for the shared installation of one home directory.
func New(home string) Manager {
	paths := platform.PathsForHome(home)
	return Manager{Home: paths.Home, Layout: paths.Install()}
}

// Stage copies the core binary at sourcePath into a private staging directory,
// verifies its SHA-256 against wantDigest while copying, verifies that the
// copied bytes are a macOS universal binary carrying both arm64 and x86_64,
// and promotes it to versions/<version> only when all of that holds. A failed
// stage promotes nothing and leaves no staging remnant. Stage never activates
// the version; that is a separate, atomic switch.
func (m Manager) Stage(ctx context.Context, sourcePath, version, wantDigest string) error {
	if !validDigest(wantDigest) {
		return errUnusableDigest
	}
	if !platform.ValidInstallVersion(version) {
		return errUnsupportedVersion
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.Layout.Root, 0o755); err != nil {
		return errInstallRoot
	}
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		return errInstallRoot
	}
	defer root.Close()

	// Every name below is relative to the verified root; nothing rejoins Root.
	staging := path.Join("staging", version)
	installed := path.Join("versions", version)

	// A crashed or hostile predecessor cannot poison this stage: whatever sits
	// at the staging name goes first, and os.Root refuses to remove or create
	// through a link that leaves the root.
	if err := root.RemoveAll(staging); err != nil {
		return errStagingRoot
	}
	if err := root.MkdirAll(staging, 0o755); err != nil {
		return errStagingRoot
	}
	discard := func(err error) error {
		_ = root.RemoveAll(staging)
		return err
	}

	digest, err := stageCore(ctx, root, staging, sourcePath, wantDigest)
	if err != nil {
		return discard(err)
	}
	manifest, err := json.Marshal(struct {
		SchemaVersion string `json:"schemaVersion"`
		Version       string `json:"version"`
		SHA256        string `json:"sha256"`
	}{SchemaVersion: manifestSchema, Version: version, SHA256: digest})
	if err != nil {
		return discard(errStagedWrite)
	}
	if err := root.WriteFile(path.Join(staging, "manifest.json"), append(manifest, '\n'), 0o644); err != nil {
		return discard(errStagedWrite)
	}

	if err := root.MkdirAll("versions", 0o755); err != nil {
		return discard(errPromote)
	}
	// Rename cannot replace a populated directory, so the previous copy of this
	// exact version goes first. Only fully verified content ever reaches here.
	if err := root.RemoveAll(installed); err != nil {
		return discard(errPromote)
	}
	if err := root.Rename(staging, installed); err != nil {
		return discard(errPromote)
	}
	return nil
}

// stageCore copies sourcePath into the staging directory, hashing the bytes as
// they are written, and verifies both the digest and the Mach-O shape of the
// copy itself. Verifying the written file — through the same descriptor that
// was hashed — is what makes a source that changes mid-copy harmless: the
// artifact is the copy, and the copy is what was checked.
func stageCore(ctx context.Context, root *os.Root, staging, sourcePath, wantDigest string) (string, error) {
	// O_NOFOLLOW rejects a symlinked source without a second lookup, and
	// O_NONBLOCK keeps a FIFO or a device from parking the caller in open(2).
	// The mode check below then rejects everything that is not a plain file.
	source, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errSourceUnreadable
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return "", errSourceUnreadable
	}
	if !info.Mode().IsRegular() {
		return "", errSourceNotRegular
	}
	if info.Size() > maxCoreSize {
		return "", errSourceTooLarge
	}

	destination, err := root.OpenFile(
		path.Join(staging, platform.CoreExecutableName),
		os.O_RDWR|os.O_CREATE|os.O_EXCL,
		0o755,
	)
	if err != nil {
		return "", errStagedWrite
	}
	defer destination.Close()

	hasher := sha256.New()
	written, err := copyBounded(ctx, io.MultiWriter(destination, hasher), source)
	if err != nil {
		return "", err
	}
	if err := destination.Sync(); err != nil {
		return "", errStagedWrite
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(digest), []byte(wantDigest)) != 1 {
		return "", errDigestMismatch
	}
	if err := verifyUniversalCore(destination, written); err != nil {
		return "", err
	}
	return digest, nil
}

// copyBounded copies at most maxCoreSize bytes, observing cancellation between
// chunks so a deadline reaches the caller instead of the disk.
func copyBounded(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, err := source.Read(buffer)
		if read > 0 {
			if total+int64(read) > maxCoreSize {
				return total, errSourceTooLarge
			}
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, errStagedWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, errSourceUnreadable
		}
	}
}

// Mach-O fat header constants (mach-o/fat.h, mach/machine.h). Fat headers are
// always big-endian on disk; the arm64 and x86_64 slices they carry are 64-bit
// Mach-O images.
const (
	fatMagic     = 0xcafebabe
	fatMagic64   = 0xcafebabf
	machOMagic64 = 0xfeedfacf
	cpuTypeX8664 = 0x01000007
	cpuTypeARM64 = 0x0100000c
	// A release fat binary carries a handful of slices; anything more is a
	// file that merely starts with the Java class-file magic 0xcafebabe.
	maxFatSlices = 16
)

// verifyUniversalCore reads the fat header of the staged copy and requires a
// real slice for both shipped architectures (design §5.2). Reading the header
// here rather than shelling out to lipo keeps the default install free of any
// external process.
func verifyUniversalCore(image io.ReaderAt, size int64) error {
	header := make([]byte, 8)
	if _, err := image.ReadAt(header, 0); err != nil {
		return errNotUniversal
	}
	magic := binary.BigEndian.Uint32(header)
	if magic != fatMagic && magic != fatMagic64 {
		return errNotUniversal
	}
	slices := binary.BigEndian.Uint32(header[4:])
	if slices == 0 || slices > maxFatSlices {
		return errNotUniversal
	}
	entrySize := 20
	if magic == fatMagic64 {
		entrySize = 32
	}
	table := make([]byte, int(slices)*entrySize)
	if _, err := image.ReadAt(table, 8); err != nil {
		return errNotUniversal
	}

	var haveARM64, haveX8664 bool
	for index := range int(slices) {
		entry := table[index*entrySize:]
		cpuType := binary.BigEndian.Uint32(entry)
		if cpuType != cpuTypeARM64 && cpuType != cpuTypeX8664 {
			continue
		}
		var offset, length uint64
		if entrySize == 32 {
			offset = binary.BigEndian.Uint64(entry[8:])
			length = binary.BigEndian.Uint64(entry[16:])
		} else {
			offset = uint64(binary.BigEndian.Uint32(entry[8:]))
			length = uint64(binary.BigEndian.Uint32(entry[12:]))
		}
		if length < 4 || offset > uint64(size) || length > uint64(size)-offset {
			return errNotUniversal
		}
		sliceMagic := make([]byte, 4)
		if _, err := image.ReadAt(sliceMagic, int64(offset)); err != nil {
			return errNotUniversal
		}
		if binary.LittleEndian.Uint32(sliceMagic) != machOMagic64 &&
			binary.BigEndian.Uint32(sliceMagic) != machOMagic64 {
			return errNotUniversal
		}
		if cpuType == cpuTypeARM64 {
			haveARM64 = true
		} else {
			haveX8664 = true
		}
	}
	if !haveARM64 || !haveX8664 {
		return errMissingSlice
	}
	return nil
}

// validDigest accepts only the exact shape hex.EncodeToString produces for a
// SHA-256 sum, so a truncated or upper-case published digest is a refusal
// rather than a silently weaker comparison.
func validDigest(digest string) bool {
	if len(digest) != hex.EncodedLen(sha256.Size) {
		return false
	}
	for _, character := range []byte(digest) {
		hexadecimal := character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
		if !hexadecimal {
			return false
		}
	}
	return true
}

// Activate makes an installed version the one adapters run. It re-verifies the
// version against its recorded digest, runs the health check, re-verifies the
// digest a second time, and only then switches the current-version pointer,
// demoting the outgoing version to previous. Any failure returns with every
// pointer untouched, so the last known-good version stays active (design §11).
func (m Manager) Activate(ctx context.Context, version string) error {
	if !platform.ValidInstallVersion(version) {
		return errUnsupportedVersion
	}
	if m.Health == nil {
		return errNoHealthCheck
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, unlock, err := m.lockedRoot()
	if err != nil {
		return err
	}
	defer unlock()

	installed := path.Join("versions", version)
	before, err := verifyInstalled(root, installed, version)
	if err != nil {
		return err
	}

	// The health check needs a name it can exec; a descriptor cannot be
	// executed here. version is an exact catalog value that already passed
	// ValidInstallVersion, so this join adds no attacker-controlled element,
	// and the digest is re-verified through the root below so a core swapped
	// during its own health check is refused rather than activated.
	executable := filepath.Join(m.Layout.VersionsDir, version, platform.CoreExecutableName)
	if err := m.Health(ctx, executable); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errHealthCheck
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	after, err := verifyInstalled(root, installed, version)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(before), []byte(after)) != 1 {
		return errDigestMismatch
	}

	outgoing, outgoingErr := readPointer(root, currentPointer)
	if err := writePointer(root, currentPointer, version); err != nil {
		return err
	}
	if outgoingErr == nil && outgoing != version {
		// A failure here leaves a coherent install: current is correct and the
		// rollback target is merely stale or missing, which doctor reports.
		_ = writePointer(root, previousPointer, outgoing)
	}
	// Retention is housekeeping, not part of the switch: the version is active
	// whether or not superseded copies could be removed.
	_ = prune(root)
	return nil
}

// Rollback exchanges the current and previous pointers, restoring the last
// known-good version. It is an exchange rather than a stack pop, so a rollback
// that turns out to be wrong is itself reversible. The restored version was
// health-checked when it was activated and is re-verified against its digest
// here; it is not re-executed, because rollback is the escape hatch used when
// running the active core is exactly what is failing.
//
// Current is written first. An interrupted rollback therefore lands on the
// restored version with previous naming that same version, which reads as "no
// rollback target" — the install runs the good version and only the ability to
// roll forward is lost.
func (m Manager) Rollback(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, unlock, err := m.lockedRoot()
	if err != nil {
		return err
	}
	defer unlock()

	current, err := readPointer(root, currentPointer)
	if err != nil {
		return err
	}
	previous, err := readPointer(root, previousPointer)
	if err != nil || previous == current {
		return errNoPrevious
	}
	if _, err := verifyInstalled(root, path.Join("versions", previous), previous); err != nil {
		return err
	}
	if err := writePointer(root, currentPointer, previous); err != nil {
		return err
	}
	return writePointer(root, previousPointer, current)
}

// Current reads the current-version pointer. The bool is false when nothing is
// installed yet; a pointer that exists but does not name a version the release
// build can produce is an error, never a path.
func (m Manager) Current() (string, bool, error) { return m.pointer(currentPointer) }

// Previous reads the rollback target. The bool is false when no previous
// known-good version is recorded.
func (m Manager) Previous() (string, bool, error) {
	version, ok, err := m.pointer(previousPointer)
	if !ok || err != nil {
		return version, ok, err
	}
	// A previous that names the active version is the residue of an
	// interrupted rollback, not a rollback target.
	if current, currentOK, _ := m.pointer(currentPointer); currentOK && current == version {
		return "", false, nil
	}
	return version, true, nil
}

func (m Manager) pointer(name string) (string, bool, error) {
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, errInstallRoot
	}
	defer root.Close()
	version, err := readPointer(root, name)
	switch {
	case errors.Is(err, errNothingActive):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return version, true, nil
}

// Prune removes installed versions other than the active one and its rollback
// target, keeping at least one previous known-good version available (design
// §5.3). It only ever removes directories under versions/, so the state
// database, bundles, reports, and quarantine are outside anything it can name.
func (m Manager) Prune() error {
	root, unlock, err := m.lockedRoot()
	if err != nil {
		return err
	}
	defer unlock()
	return prune(root)
}

// prune assumes the install lock is held.
func prune(root *os.Root) error {
	// Fail closed: without a trustworthy active version there is nothing that
	// can be shown to be superseded, so nothing is removed.
	current, err := readPointer(root, currentPointer)
	if err != nil {
		return err
	}
	keep := map[string]bool{current: true}
	if previous, err := readPointer(root, previousPointer); err == nil {
		keep[previous] = true
	}

	directory, err := root.Open("versions")
	if err != nil {
		return nil
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return errPrune
	}
	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}
		// RemoveAll through the root removes a planted symlink itself rather
		// than what it points at, and refuses anything leaving the root.
		if err := root.RemoveAll(path.Join("versions", entry.Name())); err != nil {
			return errPrune
		}
	}
	return nil
}

// lockedRoot opens the install root and takes the exclusive install lock. The
// lock is advisory and cross-process: two adapters bootstrapping at once must
// not have one run's prune remove the version the other run is switching to.
// It never waits, so a stuck installer cannot hang a second one.
func (m Manager) lockedRoot() (*os.Root, func(), error) {
	if err := os.MkdirAll(m.Layout.Root, 0o755); err != nil {
		return nil, nil, errInstallRoot
	}
	root, err := os.OpenRoot(m.Layout.Root)
	if err != nil {
		return nil, nil, errInstallRoot
	}
	guard, err := root.OpenFile(lockFile, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		root.Close()
		return nil, nil, errInstallRoot
	}
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		guard.Close()
		root.Close()
		return nil, nil, errInstallBusy
	}
	return root, func() {
		_ = syscall.Flock(int(guard.Fd()), syscall.LOCK_UN)
		guard.Close()
		root.Close()
	}, nil
}

// verifyInstalled re-establishes that an installed version is what Stage
// verified: a regular executable core whose bytes still hash to the digest its
// manifest recorded. This is the §11 "checksum failure keeps the last
// known-good active" path.
func verifyInstalled(root *os.Root, directory, version string) (string, error) {
	manifestInfo, err := root.Lstat(path.Join(directory, "manifest.json"))
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > maxManifestSize {
		return "", errManifest
	}
	raw, err := root.ReadFile(path.Join(directory, "manifest.json"))
	if err != nil {
		return "", errManifest
	}
	var manifest struct {
		SchemaVersion string `json:"schemaVersion"`
		Version       string `json:"version"`
		SHA256        string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return "", errManifest
	}
	if manifest.SchemaVersion != manifestSchema || manifest.Version != version || !validDigest(manifest.SHA256) {
		return "", errManifest
	}

	// O_NOFOLLOW keeps a version directory whose core was replaced by a link
	// from being read through it; O_NONBLOCK keeps a FIFO from parking us in
	// open(2). The mode check runs on the opened descriptor, so nothing can be
	// swapped between the check and the read.
	core, err := root.OpenFile(
		path.Join(directory, platform.CoreExecutableName),
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return "", errNotInstalled
	}
	defer core.Close()
	info, err := core.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errNotInstalled
	}
	if info.Size() > maxCoreSize {
		return "", errSourceTooLarge
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(core, maxCoreSize)); err != nil {
		return "", errNotInstalled
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(digest), []byte(manifest.SHA256)) != 1 {
		return "", errDigestMismatch
	}
	return digest, nil
}

// readPointer treats a pointer file as untrusted local state on every read: it
// is another process's writable file, so its content is re-validated before it
// is ever joined into a path.
func readPointer(root *os.Root, name string) (string, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return "", errNothingActive
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPointerSize {
		return "", errUnusablePointer
	}
	content, err := root.ReadFile(name)
	if err != nil {
		return "", errUnusablePointer
	}
	version := strings.TrimSpace(string(content))
	if !platform.ValidInstallVersion(version) {
		return "", errUnusablePointer
	}
	return version, nil
}

// writePointer replaces a pointer atomically: a fully written and flushed
// temporary is renamed over the pointer within the same directory, so a crash
// leaves either the old name or the new one, never an unparseable file and
// never an install with no way to find its binary.
func writePointer(root *os.Root, name, version string) error {
	temporary := name + pointerSuffix
	// Removing first, then creating exclusively, keeps a temporary name that
	// was pre-created as a symlink to an installed core from turning this into
	// a write primitive: Remove drops the link rather than following it.
	if err := root.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return errPointerWrite
	}
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errPointerWrite
	}
	written := func() error {
		defer file.Close()
		if _, err := file.WriteString(version + "\n"); err != nil {
			return errPointerWrite
		}
		return file.Sync()
	}()
	if written != nil {
		_ = root.Remove(temporary)
		return errPointerWrite
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return errPointerWrite
	}
	return nil
}
