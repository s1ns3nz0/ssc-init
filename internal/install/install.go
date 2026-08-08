// Package install performs staged, digest-verified core installations under
// the shared SSC Init data directory (design §5.3, §11). It never reads,
// writes, or removes the state database, intelligence bundles, reports, or
// quarantine.
//
// The core is never downloaded here: an adapter obtains the release artifact
// and its published SHA-256, and this package verifies what it was handed.
// Every install-side path is resolved through an os.Root opened on the install
// root, so no supplied name can escape it and no absolute path is rebuilt
// after that root is verified. Errors are value-free: they carry no path, no
// digest, and no version.
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
)

// Manager owns one shared installation.
type Manager struct {
	Home   string
	Layout platform.InstallLayout
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
