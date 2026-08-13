package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	managedTimeLayout = "20060102T150405.000000000Z"
	safeAuditPrefix   = "$SSC_INIT_DATA/audit/"
)

var managedArchivePattern = regexp.MustCompile(`\A([0-9]{8}T[0-9]{6}\.[0-9]{9}Z)_([0-9a-f]{32})\.zip\z`)
var auditProcessLocks sync.Map

type Stored struct {
	RunID     string
	Label     string
	SafePath  string
	SHA256    string
	State     State
	Profile   Profile
	CreatedAt time.Time
	Size      int64
	Valid     bool
}

type Manager struct {
	Root   string
	Home   string
	Now    func() time.Time
	Random io.Reader
	Render func(Record) ([]byte, error)

	retentionAge   time.Duration
	retentionBytes int64
}

func (m *Manager) Save(ctx context.Context, record Record) (Stored, error) {
	if err := ctx.Err(); err != nil {
		return Stored{}, err
	}
	if m == nil || m.Now == nil || m.Random == nil || m.Render == nil {
		return Stored{}, errors.New("invalid audit manager")
	}
	report, err := m.Render(record)
	if err != nil {
		return Stored{}, errors.New("audit rendering failed")
	}
	encoded, err := Encode(record, report)
	if err != nil {
		return Stored{}, err
	}
	unlockProcess := lockAuditProcess(m.Root)
	defer unlockProcess()
	root, err := m.openRoot(true)
	if err != nil {
		return Stored{}, err
	}
	defer root.Close()
	unlock, err := lockAuditRoot(root)
	if err != nil {
		return Stored{}, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return Stored{}, err
	}
	created := m.Now().UTC()
	name, err := managedArchiveName(created, record.Run.ID)
	if err != nil {
		return Stored{}, err
	}
	if _, err := root.Lstat(name); err == nil || !os.IsNotExist(err) {
		return Stored{}, errors.New("audit archive already exists")
	}
	temporary, err := m.temporaryName()
	if err != nil {
		return Stored{}, err
	}
	file, err := root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return Stored{}, errors.New("cannot create audit archive")
	}
	cleanup := func() {
		_ = file.Close()
		_ = root.Remove(temporary)
	}
	if _, err := file.Write(encoded); err != nil || file.Sync() != nil {
		cleanup()
		return Stored{}, errors.New("cannot write audit archive")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		cleanup()
		return Stored{}, errors.New("invalid temporary audit archive")
	}
	verified, err := Verify(file, info.Size())
	if err != nil || verified.Record.Run.ID != record.Run.ID {
		cleanup()
		return Stored{}, errors.New("temporary audit archive failed verification")
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return Stored{}, err
	}
	if err := file.Close(); err != nil {
		_ = root.Remove(temporary)
		return Stored{}, errors.New("cannot close audit archive")
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return Stored{}, errors.New("cannot publish audit archive")
	}
	if err := syncRoot(root); err != nil {
		return Stored{}, errors.New("cannot sync audit archive directory")
	}
	published, err := verifyRootFile(root, name)
	if err != nil || published.ZIPSHA256 != verified.ZIPSHA256 {
		return Stored{}, errors.New("published audit archive failed verification")
	}
	if err := m.pruneLocked(ctx, root); err != nil {
		return Stored{}, err
	}
	return storedFromVerified(name, created, info.Size(), published), nil
}

func (m *Manager) List(ctx context.Context) ([]Stored, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("invalid audit manager")
	}
	unlockProcess := lockAuditProcess(m.Root)
	defer unlockProcess()
	root, err := m.openRoot(true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	unlock, err := lockAuditRoot(root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return listLocked(ctx, root)
}

func (m *Manager) Open(ctx context.Context, runID string) (Verified, error) {
	if err := ctx.Err(); err != nil {
		return Verified{}, err
	}
	if m == nil || !runIDPattern.MatchString(runID) {
		return Verified{}, errors.New("invalid audit run ID")
	}
	unlockProcess := lockAuditProcess(m.Root)
	defer unlockProcess()
	root, err := m.openRoot(false)
	if err != nil {
		return Verified{}, err
	}
	defer root.Close()
	unlock, err := lockAuditRoot(root)
	if err != nil {
		return Verified{}, err
	}
	defer unlock()
	listed, err := listLocked(ctx, root)
	if err != nil {
		return Verified{}, err
	}
	for _, stored := range listed {
		if stored.RunID == runID && stored.Valid {
			name := strings.TrimPrefix(stored.SafePath, safeAuditPrefix)
			return verifyRootFile(root, name)
		}
	}
	return Verified{}, errors.New("audit archive not found")
}

func (m *Manager) Export(ctx context.Context, runID, absoluteOutput string, redacted bool) (Stored, error) {
	if err := ctx.Err(); err != nil {
		return Stored{}, err
	}
	if m == nil || m.Now == nil || m.Random == nil || m.Render == nil || !runIDPattern.MatchString(runID) || !filepath.IsAbs(absoluteOutput) || filepath.Clean(absoluteOutput) != absoluteOutput || !validExportBase(filepath.Base(absoluteOutput)) {
		return Stored{}, errors.New("invalid audit export")
	}
	unlockProcess := lockAuditProcess(m.Root)
	defer unlockProcess()
	root, err := m.openRoot(false)
	if err != nil {
		return Stored{}, err
	}
	defer root.Close()
	unlock, err := lockAuditRoot(root)
	if err != nil {
		return Stored{}, err
	}
	defer unlock()
	listed, err := listLocked(ctx, root)
	if err != nil {
		return Stored{}, err
	}
	var sourceName string
	for _, stored := range listed {
		if stored.RunID == runID && stored.Valid {
			sourceName = strings.TrimPrefix(stored.SafePath, safeAuditPrefix)
			break
		}
	}
	if sourceName == "" {
		return Stored{}, errors.New("audit archive not found")
	}
	sourceBytes, sourceVerified, err := readVerifiedRootFile(root, sourceName)
	if err != nil {
		return Stored{}, err
	}
	outputBytes := sourceBytes
	outputVerified := sourceVerified
	if redacted {
		var salt [32]byte
		if _, err := io.ReadFull(m.Random, salt[:]); err != nil {
			return Stored{}, errors.New("audit randomness unavailable")
		}
		transformed, err := Redact(sourceVerified.Record, salt)
		if err != nil {
			return Stored{}, err
		}
		report, err := m.Render(transformed)
		if err != nil {
			return Stored{}, errors.New("audit rendering failed")
		}
		outputBytes, err = Encode(transformed, report)
		if err != nil {
			return Stored{}, err
		}
		outputVerified, err = Verify(bytes.NewReader(outputBytes), int64(len(outputBytes)))
		if err != nil {
			return Stored{}, errors.New("redacted audit verification failed")
		}
	}
	if err := ctx.Err(); err != nil {
		return Stored{}, err
	}
	if err := m.publishExport(absoluteOutput, outputBytes); err != nil {
		return Stored{}, err
	}
	return Stored{RunID: outputVerified.Record.Run.ID, Label: outputVerified.Record.Run.Label, SHA256: outputVerified.ZIPSHA256, State: outputVerified.Record.State, Profile: outputVerified.Record.Profile, CreatedAt: m.Now().UTC(), Size: int64(len(outputBytes)), Valid: true}, nil
}

func (m *Manager) Prune(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || m.Now == nil {
		return errors.New("invalid audit manager")
	}
	unlockProcess := lockAuditProcess(m.Root)
	defer unlockProcess()
	root, err := m.openRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockAuditRoot(root)
	if err != nil {
		return err
	}
	defer unlock()
	return m.pruneLocked(ctx, root)
}

func (m *Manager) pruneLocked(ctx context.Context, root *os.Root) error {
	listed, err := listLocked(ctx, root)
	if err != nil {
		return err
	}
	valid := make([]Stored, 0, len(listed))
	for _, stored := range listed {
		if stored.Valid {
			valid = append(valid, stored)
		}
	}
	if len(valid) <= 1 {
		return nil
	}
	age := m.retentionAge
	if age == 0 {
		age = 30 * 24 * time.Hour
	}
	limit := m.retentionBytes
	if limit == 0 {
		limit = 1 << 30
	}
	now := m.Now().UTC()
	remove := make(map[string]bool)
	var total int64
	for _, stored := range valid {
		total += stored.Size
	}
	for index := len(valid) - 1; index >= 1; index-- {
		stored := valid[index]
		if now.Sub(stored.CreatedAt) > age || total > limit {
			remove[stored.SafePath] = true
			total -= stored.Size
		}
	}
	for _, stored := range valid {
		if !remove[stored.SafePath] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := root.Remove(strings.TrimPrefix(stored.SafePath, safeAuditPrefix)); err != nil {
			return errors.New("cannot prune audit archive")
		}
	}
	if len(remove) > 0 {
		return syncRoot(root)
	}
	return nil
}

func (m *Manager) openRoot(create bool) (*os.Root, error) {
	if m == nil || !filepath.IsAbs(m.Home) || filepath.Clean(m.Root) != filepath.Join(filepath.Clean(m.Home), "Library", "Application Support", "SSC Init", "audit") {
		return nil, errors.New("invalid audit root")
	}
	homeInfo, err := os.Lstat(m.Home)
	if err != nil || !homeInfo.IsDir() || homeInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe audit home")
	}
	current, err := os.OpenRoot(m.Home)
	if err != nil {
		return nil, errors.New("cannot open audit home")
	}
	openedHome, err := current.Lstat(".")
	if err != nil || !os.SameFile(homeInfo, openedHome) {
		current.Close()
		return nil, errors.New("audit home identity changed")
	}
	for _, component := range []string{"Library", "Application Support", "SSC Init", "audit"} {
		info, statErr := current.Lstat(component)
		if os.IsNotExist(statErr) && create {
			if err := current.Mkdir(component, 0o700); err != nil && !os.IsExist(err) {
				current.Close()
				return nil, errors.New("cannot create audit root")
			}
			info, statErr = current.Lstat(component)
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, errors.New("unsafe audit root")
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			current.Close()
			return nil, errors.New("cannot open audit root")
		}
		opened, err := next.Lstat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			current.Close()
			return nil, errors.New("audit root identity changed")
		}
		current.Close()
		current = next
	}
	return current, nil
}

func (m *Manager) temporaryName() (string, error) {
	random := make([]byte, 16)
	if _, err := io.ReadFull(m.Random, random); err != nil {
		return "", errors.New("audit randomness unavailable")
	}
	return ".tmp-" + hex.EncodeToString(random), nil
}

func lockAuditRoot(root *os.Root) (func(), error) {
	var file *os.File
	for attempt := 0; attempt < 4; attempt++ {
		opened, err := root.OpenFile(".lock", os.O_RDWR|unix.O_NOFOLLOW, 0)
		if err == nil {
			file = opened
			break
		}
		if !os.IsNotExist(err) {
			return nil, errors.New("cannot open audit lock")
		}
		created, createErr := root.OpenFile(".lock", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
		if createErr == nil {
			file = created
			break
		}
		if !os.IsExist(createErr) {
			return nil, errors.New("cannot create audit lock")
		}
	}
	if file == nil {
		return nil, errors.New("cannot open audit lock")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("invalid audit lock")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, errors.New("cannot lock audit root")
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func lockAuditProcess(root string) func() {
	key := filepath.Clean(root)
	value, _ := auditProcessLocks.LoadOrStore(key, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

func listLocked(ctx context.Context, root *os.Root) ([]Stored, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, errors.New("cannot list audit root")
	}
	entries, err := directory.ReadDir(maxManagedArchives + 1)
	directory.Close()
	if err != nil && err != io.EOF {
		return nil, errors.New("cannot list audit root")
	}
	if len(entries) > maxManagedArchives {
		return nil, errors.New("too many managed audit archives")
	}
	result := make([]Stored, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		match := managedArchivePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		created, parseErr := time.Parse(managedTimeLayout, match[1])
		stored := Stored{RunID: "run:hex:" + match[2], SafePath: safeAuditPrefix + entry.Name(), CreatedAt: created}
		info, statErr := root.Lstat(entry.Name())
		if parseErr != nil || statErr != nil {
			result = append(result, stored)
			continue
		}
		stored.Size = info.Size()
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			result = append(result, stored)
			continue
		}
		verified, verifyErr := verifyRootFile(root, entry.Name())
		if verifyErr == nil && verified.Record.Run.ID == stored.RunID {
			stored = storedFromVerified(entry.Name(), created, info.Size(), verified)
		}
		result = append(result, stored)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].SafePath > result[j].SafePath
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

const maxManagedArchives = 10000

func verifyRootFile(root *os.Root, name string) (Verified, error) {
	_, verified, err := readVerifiedRootFile(root, name)
	return verified, err
}

func readVerifiedRootFile(root *os.Root, name string) ([]byte, Verified, error) {
	expected, err := root.Lstat(name)
	if err != nil || !expected.Mode().IsRegular() || expected.Mode().Perm() != 0o600 || expected.Size() < 1 || expected.Size() > maxArchiveBytes {
		return nil, Verified{}, errors.New("invalid managed audit archive")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, Verified{}, errors.New("cannot open managed audit archive")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) {
		return nil, Verified{}, errors.New("managed audit archive identity changed")
	}
	verified, err := Verify(file, opened.Size())
	if err != nil {
		return nil, Verified{}, err
	}
	contents := make([]byte, opened.Size())
	if _, err := file.ReadAt(contents, 0); err != nil {
		return nil, Verified{}, errors.New("cannot read managed audit archive")
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != verified.ZIPSHA256 {
		return nil, Verified{}, errors.New("managed audit archive changed")
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(opened, pathAfter) || after.Size() != opened.Size() {
		return nil, Verified{}, errors.New("managed audit archive changed")
	}
	return contents, verified, nil
}

func managedArchiveName(created time.Time, runID string) (string, error) {
	if !runIDPattern.MatchString(runID) {
		return "", errors.New("invalid audit run ID")
	}
	return created.UTC().Format(managedTimeLayout) + "_" + strings.TrimPrefix(runID, "run:hex:") + ".zip", nil
}

func storedFromVerified(name string, created time.Time, size int64, verified Verified) Stored {
	return Stored{RunID: verified.Record.Run.ID, Label: verified.Record.Run.Label, SafePath: safeAuditPrefix + name, SHA256: verified.ZIPSHA256, State: verified.Record.State, Profile: verified.Record.Profile, CreatedAt: created.UTC(), Size: size, Valid: true}
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (m *Manager) publishExport(output string, contents []byte) error {
	parent, err := openSafeAbsoluteDirectory(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer parent.Close()
	base := filepath.Base(output)
	if info, err := parent.Lstat(base); err == nil && info != nil || !os.IsNotExist(err) {
		return errors.New("audit export already exists")
	}
	random := make([]byte, 16)
	if _, err := io.ReadFull(m.Random, random); err != nil {
		return errors.New("audit randomness unavailable")
	}
	temporary := "." + base + ".tmp-" + hex.EncodeToString(random)
	file, err := parent.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("cannot create audit export")
	}
	cleanup := func() {
		_ = file.Close()
		_ = parent.Remove(temporary)
	}
	if _, err := file.Write(contents); err != nil || file.Sync() != nil {
		cleanup()
		return errors.New("cannot write audit export")
	}
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0o600 {
		cleanup()
		return errors.New("invalid audit export")
	}
	if _, err := Verify(file, info.Size()); err != nil {
		cleanup()
		return errors.New("audit export verification failed")
	}
	if err := file.Close(); err != nil {
		_ = parent.Remove(temporary)
		return errors.New("cannot close audit export")
	}
	if err := parent.Link(temporary, base); err != nil {
		_ = parent.Remove(temporary)
		return errors.New("cannot publish audit export")
	}
	if err := parent.Remove(temporary); err != nil {
		return errors.New("cannot finalize audit export")
	}
	verified, err := verifyRootFile(parent, base)
	if err != nil {
		return errors.New("published audit export failed verification")
	}
	digest := sha256.Sum256(contents)
	if verified.ZIPSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("published audit export changed")
	}
	return syncRoot(parent)
}

func validExportBase(base string) bool {
	return base != "" && base != "." && base != ".." && base != string(filepath.Separator)
}

func openSafeAbsoluteDirectory(directory string) (*os.Root, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("unsafe audit export parent")
	}
	volume := filepath.VolumeName(directory)
	rootPath := volume + string(filepath.Separator)
	relative, err := filepath.Rel(rootPath, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("unsafe audit export parent")
	}
	current, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, errors.New("cannot open audit export parent")
	}
	if relative == "." {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, errors.New("unsafe audit export parent")
		}
		info, err := current.Lstat(component)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, errors.New("unsafe audit export parent")
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			current.Close()
			return nil, errors.New("cannot open audit export parent")
		}
		opened, err := next.Lstat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			current.Close()
			return nil, errors.New("audit export parent identity changed")
		}
		current.Close()
		current = next
	}
	return current, nil
}
