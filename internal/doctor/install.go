package doctor

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const (
	installManifestSchema = "ssc-init.install.manifest.v1"
	maxInstallManifest    = 4096
	maxInstalledCore      = 512 << 20
	maxInstallPointer     = 128
)

var errInstallReport = errors.New("managed installation cannot be read")

// InstallReport reads the managed installation without creating files,
// acquiring the install lock, or executing the installed core. Invalid or
// unreadable pointer state is an error; a missing or digest-mismatched active
// core is represented as Managed with IntegrityVerified false so doctor can
// explain the degraded state without exposing a path or digest.
func InstallReport(home string) (Install, error) {
	layout := platform.PathsForHome(home).Install()
	root, err := os.OpenRoot(layout.Root)
	if errors.Is(err, os.ErrNotExist) {
		return Install{}, nil
	}
	if err != nil {
		return Install{}, errInstallReport
	}
	defer root.Close()

	current, present, err := installPointer(root, "current")
	if err != nil {
		return Install{}, errInstallReport
	}
	if !present {
		return Install{}, nil
	}

	report := Install{Managed: true, CurrentVersion: current}
	if previous, ok, err := installPointer(root, "previous"); err != nil {
		return Install{}, errInstallReport
	} else if ok && previous != current {
		report.PreviousVersion = previous
		report.RollbackAvailable = installIntegrity(root, previous)
	}
	report.VersionsInstalled = installedVersionCount(root)
	report.IntegrityVerified = installIntegrity(root, current)
	return report, nil
}

func installPointer(root *os.Root, name string) (string, bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxInstallPointer {
		return "", false, errInstallReport
	}
	raw, err := root.ReadFile(name)
	if err != nil {
		return "", false, errInstallReport
	}
	version := strings.TrimSuffix(string(raw), "\n")
	if !platform.ValidInstallVersion(version) {
		return "", false, errInstallReport
	}
	return version, true, nil
}

func installedVersionCount(root *os.Root) int {
	directory, err := root.Open("versions")
	if err != nil {
		return 0
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() && platform.ValidInstallVersion(entry.Name()) {
			count++
		}
	}
	return count
}

func installIntegrity(root *os.Root, version string) bool {
	directory := path.Join("versions", version)
	manifestInfo, err := root.Lstat(path.Join(directory, "manifest.json"))
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > maxInstallManifest {
		return false
	}
	raw, err := root.ReadFile(path.Join(directory, "manifest.json"))
	if err != nil {
		return false
	}
	var manifest struct {
		SchemaVersion string `json:"schemaVersion"`
		Version       string `json:"version"`
		SHA256        string `json:"sha256"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != installManifestSchema ||
		manifest.Version != version || !validInstallDigest(manifest.SHA256) {
		return false
	}

	core, err := root.OpenFile(path.Join(directory, platform.CoreExecutableName), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer core.Close()
	info, err := core.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Size() > maxInstalledCore {
		return false
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(core, maxInstalledCore+1)); err != nil {
		return false
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(digest), []byte(manifest.SHA256)) == 1
}

func validInstallDigest(digest string) bool {
	if len(digest) != hex.EncodedLen(sha256.Size) {
		return false
	}
	for _, character := range []byte(digest) {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
