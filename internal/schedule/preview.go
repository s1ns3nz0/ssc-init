package schedule

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

const (
	SchemaV1 = "ssc-init.schedule-preview.v1"
	Label    = "com.s1ns3nz0.ssc-init.daily"
)

var ErrInvalidSchedule = errors.New("invalid schedule configuration")

type Preview struct {
	SchemaVersion  string   `json:"schemaVersion"`
	Label          string   `json:"label"`
	Command        []string `json:"command"`
	Hour           int      `json:"hour"`
	Minute         int      `json:"minute"`
	StandardOut    string   `json:"standardOut"`
	StandardError  string   `json:"standardError"`
	RemovalCommand string   `json:"removalCommand"`
	Capability     string   `json:"capability"`
}

type Manager struct {
	Home       string
	Executable string
	UID        int
	Runner     platform.Runner
}

func (m Manager) Preview() (Preview, error) {
	cleanHome, cleanExecutable := filepath.Clean(m.Home), filepath.Clean(m.Executable)
	versions := filepath.Join(cleanHome, "Library", "Application Support", "SSC Init", "core", "versions")
	relative, err := filepath.Rel(versions, cleanExecutable)
	if err != nil {
		return Preview{}, ErrInvalidSchedule
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 2 || !platform.ValidInstallVersion(parts[0]) || parts[1] != platform.CoreExecutableName {
		return Preview{}, ErrInvalidSchedule
	}
	info, err := os.Lstat(cleanExecutable)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return Preview{}, ErrInvalidSchedule
	}
	tokenized := platform.RedactHome(cleanHome, cleanExecutable)
	if !strings.HasPrefix(tokenized, "$HOME/") {
		return Preview{}, ErrInvalidSchedule
	}
	preview := Preview{
		SchemaVersion: SchemaV1, Label: Label,
		Command: []string{filepath.ToSlash(tokenized), "scan", "--baseline", "--json"},
		Hour:    9, Minute: 0,
		StandardOut:    "$HOME/Library/Application Support/SSC Init/reports/daily.stdout.log",
		StandardError:  "$HOME/Library/Application Support/SSC Init/reports/daily.stderr.log",
		RemovalCommand: "ssc-init schedule remove --json", Capability: "scheduled",
	}
	if !preview.Valid() {
		return Preview{}, ErrInvalidSchedule
	}
	return preview, nil
}

func (p Preview) Valid() bool {
	if p.SchemaVersion != SchemaV1 || p.Label != Label || p.Hour < 0 || p.Hour > 23 || p.Minute < 0 || p.Minute > 59 || p.Capability != "scheduled" || p.RemovalCommand != "ssc-init schedule remove --json" || len(p.Command) != 4 {
		return false
	}
	if !strings.HasPrefix(p.Command[0], "$HOME/") || filepath.Base(p.Command[0]) != platform.CoreExecutableName || !reflect.DeepEqual(p.Command[1:], []string{"scan", "--baseline", "--json"}) {
		return false
	}
	for _, value := range []string{p.Command[0], p.StandardOut, p.StandardError} {
		if !safeTokenizedPath(value) {
			return false
		}
	}
	return strings.HasSuffix(p.StandardOut, "/daily.stdout.log") && strings.HasSuffix(p.StandardError, "/daily.stderr.log")
}

func safeTokenizedPath(value string) bool {
	if !strings.HasPrefix(value, "$HOME/") || strings.Contains(value, "../") || strings.ContainsRune(value, '\x00') || privacy.ContainsSensitiveValue(value) {
		return false
	}
	relative := strings.TrimPrefix(value, "$HOME/")
	return relative != "" && filepath.ToSlash(filepath.Clean(relative)) == relative
}
