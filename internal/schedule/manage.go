package schedule

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const ResultSchemaV1 = "ssc-init.schedule-result.v1"

type Status string

const (
	StatusInstalled        Status = "installed"
	StatusAlreadyInstalled Status = "already-installed"
	StatusRemoved          Status = "removed"
	StatusNotInstalled     Status = "not-installed"
)

var (
	ErrUnsafeScheduleState = errors.New("unsafe schedule state")
	ErrScheduleCommand     = errors.New("schedule command failed")
)

var scheduleProcessLock = make(chan struct{}, 1)

type Result struct {
	SchemaVersion string  `json:"schemaVersion"`
	Label         string  `json:"label"`
	Status        Status  `json:"status"`
	Preview       Preview `json:"preview"`
}

func (r Result) Valid() bool {
	return r.SchemaVersion == ResultSchemaV1 && r.Label == Label && r.Preview.Valid() && (r.Status == StatusInstalled || r.Status == StatusAlreadyInstalled || r.Status == StatusRemoved || r.Status == StatusNotInstalled)
}

func (m Manager) Install(ctx context.Context) (Result, error) {
	preview, err := m.Preview()
	if err != nil || m.Runner == nil || m.UID < 0 {
		return Result{}, ErrInvalidSchedule
	}
	unlockProcess, err := acquireProcessLock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlockProcess()
	root, err := m.launchAgentsRoot(true)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	unlock, err := acquireScheduleLock(ctx, root)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	want := renderPlist(m, preview)
	name := Label + ".plist"
	existing, exists, err := readExactRegular(root, name)
	if err != nil {
		return Result{}, err
	}
	if exists && !bytes.Equal(existing, want) {
		return Result{}, ErrUnsafeScheduleState
	}
	if !exists {
		if err := publishAtomic(root, name, want); err != nil {
			return Result{}, err
		}
	}
	result := Result{SchemaVersion: ResultSchemaV1, Label: Label, Preview: preview, Status: StatusInstalled}
	domain, service := m.domain(), m.domain()+"/"+Label
	if commandSucceeded(m.Runner.Run(ctx, "/bin/launchctl", "print", service)) {
		result.Status = StatusAlreadyInstalled
		return result, nil
	}
	if !commandSucceeded(m.Runner.Run(ctx, "/bin/launchctl", "bootstrap", domain, m.plistPath())) {
		if !exists {
			_ = root.Remove(name)
		}
		return Result{}, ErrScheduleCommand
	}
	return result, nil
}

func (m Manager) Remove(ctx context.Context) (Result, error) {
	preview, err := m.Preview()
	if err != nil || m.Runner == nil || m.UID < 0 {
		return Result{}, ErrInvalidSchedule
	}
	unlockProcess, err := acquireProcessLock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlockProcess()
	root, err := m.launchAgentsRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return Result{SchemaVersion: ResultSchemaV1, Label: Label, Status: StatusNotInstalled, Preview: preview}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	unlock, err := acquireScheduleLock(ctx, root)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	name := Label + ".plist"
	existing, exists, err := readExactRegular(root, name)
	if err != nil {
		return Result{}, err
	}
	if !exists {
		return Result{SchemaVersion: ResultSchemaV1, Label: Label, Status: StatusNotInstalled, Preview: preview}, nil
	}
	if !bytes.Equal(existing, renderPlist(m, preview)) {
		return Result{}, ErrUnsafeScheduleState
	}
	if commandSucceeded(m.Runner.Run(ctx, "/bin/launchctl", "print", m.domain()+"/"+Label)) {
		if !commandSucceeded(m.Runner.Run(ctx, "/bin/launchctl", "bootout", m.domain(), m.plistPath())) {
			return Result{}, ErrScheduleCommand
		}
	}
	if err := root.Remove(name); err != nil {
		return Result{}, ErrUnsafeScheduleState
	}
	return Result{SchemaVersion: ResultSchemaV1, Label: Label, Status: StatusRemoved, Preview: preview}, nil
}

func acquireProcessLock(ctx context.Context) (func(), error) {
	select {
	case scheduleProcessLock <- struct{}{}:
		return func() { <-scheduleProcessLock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func commandSucceeded(_ platform.CommandResult, err error) bool { return err == nil }

func (m Manager) domain() string { return "gui/" + strconv.Itoa(m.UID) }
func (m Manager) plistPath() string {
	return filepath.Join(m.Home, "Library", "LaunchAgents", Label+".plist")
}

func (m Manager) launchAgentsRoot(create bool) (*os.Root, error) {
	home, err := verifiedRoot(m.Home)
	if err != nil {
		return nil, err
	}
	current := home
	for _, component := range []string{"Library", "LaunchAgents"} {
		expected, statErr := current.Lstat(component)
		if errors.Is(statErr, fs.ErrNotExist) && create {
			if statErr = current.Mkdir(component, 0o700); statErr != nil && !errors.Is(statErr, fs.ErrExist) {
				current.Close()
				return nil, ErrUnsafeScheduleState
			}
			expected, statErr = current.Lstat(component)
		}
		if statErr != nil {
			current.Close()
			return nil, statErr
		}
		if expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
			current.Close()
			return nil, ErrUnsafeScheduleState
		}
		child, openErr := current.OpenRoot(component)
		if openErr != nil {
			current.Close()
			return nil, ErrUnsafeScheduleState
		}
		opened, openErr := child.Lstat(".")
		if openErr != nil || !os.SameFile(expected, opened) {
			child.Close()
			current.Close()
			return nil, ErrUnsafeScheduleState
		}
		current.Close()
		current = child
	}
	return current, nil
}

func verifiedRoot(name string) (*os.Root, error) {
	expected, err := os.Lstat(name)
	if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
		return nil, ErrUnsafeScheduleState
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, ErrUnsafeScheduleState
	}
	opened, err := root.Lstat(".")
	if err != nil || !os.SameFile(expected, opened) {
		root.Close()
		return nil, ErrUnsafeScheduleState
	}
	return root, nil
}

func readExactRegular(root *os.Root, name string) ([]byte, bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 64<<10 {
		return nil, false, ErrUnsafeScheduleState
	}
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, ErrUnsafeScheduleState
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, ErrUnsafeScheduleState
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, false, ErrUnsafeScheduleState
	}
	return raw, true, nil
}

func publishAtomic(root *os.Root, name string, content []byte) error {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return ErrUnsafeScheduleState
	}
	temporary := "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrUnsafeScheduleState
	}
	cleanup := true
	defer func() {
		file.Close()
		if cleanup {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(content); err != nil || file.Sync() != nil || file.Chmod(0o600) != nil || file.Close() != nil {
		return ErrUnsafeScheduleState
	}
	if err := root.Link(temporary, name); err != nil {
		return ErrUnsafeScheduleState
	}
	if err := root.Remove(temporary); err != nil {
		_ = root.Remove(name)
		return ErrUnsafeScheduleState
	}
	cleanup = false
	return nil
}

func acquireScheduleLock(ctx context.Context, root *os.Root) (func(), error) {
	const name = ".ssc-init.schedule.lock"
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrUnsafeScheduleState
	}
	info, statErr := root.Lstat(name)
	opened, openErr := file.Stat()
	if statErr != nil || openErr != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !os.SameFile(info, opened) {
		file.Close()
		return nil, ErrUnsafeScheduleState
	}
	for {
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return func() {
				_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func renderPlist(m Manager, preview Preview) []byte {
	expand := func(value string) string {
		return filepath.Join(m.Home, filepath.FromSlash(strings.TrimPrefix(value, "$HOME/")))
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>scan</string><string>--baseline</string><string>--json</string></array>
<key>StartCalendarInterval</key><dict><key>Hour</key><integer>%d</integer><key>Minute</key><integer>%d</integer></dict>
<key>StandardOutPath</key><string>%s</string>
<key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, Label, xmlText(m.Executable), preview.Hour, preview.Minute, xmlText(expand(preview.StandardOut)), xmlText(expand(preview.StandardError))))
}

func xmlText(value string) string {
	var output bytes.Buffer
	if err := xml.EscapeText(&output, []byte(value)); err != nil {
		return ""
	}
	return output.String()
}
