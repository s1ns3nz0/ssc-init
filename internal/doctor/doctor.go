// Package doctor provides read-only installation and coverage diagnostics.
package doctor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/store"
	"golang.org/x/sys/unix"
)

const schemaVersion = "ssc-init.doctor.v1"

// Path describes one redacted SSC Init-owned path.
type Path struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// StoreUsage is the local store's share of the design's 500 MB storage budget:
// sizes and counts only, never locations.
type StoreUsage struct {
	// SizeBytes covers the database and its write-ahead log and shared-memory
	// files, which the database size alone understates.
	SizeBytes int64 `json:"sizeBytes"`
	// ReclaimableBytes is space that pruning released but that a gated rewrite
	// has not yet handed back. A large figure that never drops means the gate
	// is not opening and the store is creeping upward.
	ReclaimableBytes             int64 `json:"reclaimableBytes"`
	SnapshotCount                int   `json:"snapshotCount"`
	SnapshotRetentionSeconds     int64 `json:"snapshotRetentionSeconds"`
	AssetHistoryRetentionSeconds int64 `json:"assetHistoryRetentionSeconds"`
}

// Result is the stable doctor JSON contract. Fatal is an internal signal and is
// never serialized.
type Result struct {
	SchemaVersion             string     `json:"schemaVersion"`
	Product                   string     `json:"product"`
	Version                   string     `json:"version"`
	Status                    string     `json:"status"`
	GOOS                      string     `json:"goos"`
	GOARCH                    string     `json:"goarch"`
	DatabaseDirectoryWritable bool       `json:"databaseDirectoryWritable"`
	Store                     StoreUsage `json:"store"`
	CorePaths                 []Path     `json:"corePaths"`
	Ecosystems                []string   `json:"ecosystems"`
	MissingOptionalCommands   []string   `json:"missingOptionalCommands"`
	Fatal                     bool       `json:"-"`
}

// Config supplies paths and read-only operating-system probes.
type Config struct {
	Product           string
	Version           string
	Paths             platform.Paths
	DatabasePath      string
	Ecosystems        []string
	OptionalCommands  []string
	LookPath          func(string) (string, error)
	DirectoryWritable func(string) bool
}

// Checker evaluates Config without creating files or reading asset contents.
type Checker struct{ config Config }

// New constructs a read-only checker.
func New(config Config) *Checker {
	if config.Product == "" {
		config.Product = "SSC Init"
	}
	if config.Version == "" {
		config.Version = "dev"
	}
	if config.DatabasePath == "" && config.Paths.DataDir != "" {
		config.DatabasePath = filepath.Join(config.Paths.DataDir, "state.db")
	}
	if config.LookPath == nil {
		config.LookPath = exec.LookPath
	}
	if config.DirectoryWritable == nil {
		config.DirectoryWritable = directoryWritable
	}
	return &Checker{config: config}
}

// Check returns diagnostics without mutating the host.
func (c *Checker) Check(ctx context.Context) Result {
	result := Result{
		SchemaVersion: schemaVersion,
		Product:       c.config.Product,
		Version:       c.config.Version,
		Status:        "ready",
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		CorePaths: []Path{
			{Name: "data", Path: platform.RedactHome(c.config.Paths.Home, c.config.Paths.DataDir)},
			{Name: "database", Path: platform.RedactHome(c.config.Paths.Home, c.config.DatabasePath)},
		},
		Ecosystems:              uniqueSorted(c.config.Ecosystems),
		MissingOptionalCommands: []string{},
	}
	if err := ctx.Err(); err != nil {
		result.Status = "degraded"
		result.Fatal = true
		return result
	}
	result.DatabaseDirectoryWritable = c.config.Paths.DataDir != "" && c.config.DirectoryWritable(c.config.Paths.DataDir)
	if !result.DatabaseDirectoryWritable {
		result.Status = "degraded"
	}
	usage, usageErr := storeUsage(ctx, c.config.DatabasePath, store.Options{})
	result.Store = usage
	if usageErr != nil {
		result.Status = "degraded"
	}
	for _, command := range uniqueSorted(c.config.OptionalCommands) {
		if err := ctx.Err(); err != nil {
			result.Status = "degraded"
			result.Fatal = true
			return result
		}
		if _, err := c.config.LookPath(command); err != nil {
			result.MissingOptionalCommands = append(result.MissingOptionalCommands, command)
		}
	}
	return result
}

// storeUsage measures the store without creating or migrating one, and reports
// the windows the given options select. The windows come back populated even
// when measurement fails, because they are construction-time settings rather
// than something read off disk. Check passes the documented defaults: the binary
// opens the store with store.Open, and policy-configurable retention does not
// exist yet.
func storeUsage(ctx context.Context, databasePath string, options store.Options) (StoreUsage, error) {
	usage, err := store.UsageAt(ctx, databasePath, options)
	return StoreUsage{
		SizeBytes:                    usage.SizeBytes,
		ReclaimableBytes:             usage.ReclaimableBytes,
		SnapshotCount:                usage.SnapshotCount,
		SnapshotRetentionSeconds:     int64(usage.SnapshotRetention / time.Second),
		AssetHistoryRetentionSeconds: int64(usage.AssetHistoryRetention / time.Second),
	}, err
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func directoryWritable(path string) bool {
	return directoryWritableWith(path, os.Stat, unix.Access)
}

func directoryWritableWith(path string, stat func(string) (os.FileInfo, error), access func(string, uint32) error) bool {
	current := filepath.Clean(path)
	for {
		info, err := stat(current)
		if err == nil {
			return info.IsDir() && access(current, unix.W_OK|unix.X_OK) == nil
		}
		if !os.IsNotExist(err) {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}
