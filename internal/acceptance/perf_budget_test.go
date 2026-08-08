//go:build perfbudget

// Package acceptance's performance budget harness is behind the `perfbudget`
// build tag: wall-clock numbers vary far too much between CI runners and
// developer laptops for hard budget assertions, and a flaky performance test
// trains people to ignore failures. The tag is the only mechanism that keeps
// the timing code out of the default test binary entirely — `testing.Short()`
// would still run under this repository's documented gate
// (`go test ./... -count=1`, no `-short`), and a `-run`-only entry point still
// executes under `go test ./...`.
//
// Run it on demand:
//
//	go test ./internal/acceptance -tags perfbudget -run TestPerformanceBudgets -v -count=1
package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// perfBulkFiles and perfBulkFileBytes size the synthetic payload tree so that
// content hashing, not process startup, dominates the measured scan.
const (
	perfBulkFiles     = 256
	perfBulkFileBytes = 512 << 10
)

// maxWarmRatio is the largest warm/cold wall-time ratio accepted as evidence
// that the content cache did its job. A bare "strictly faster" comparison is
// not enough: with the second run's reads served from the OS page cache, a
// deliberately cold second scan still measured a 0.955 ratio here, so `<1`
// would have passed with the cache doing nothing. The payload tree above is
// sized so re-hashing dominates the cold scan, which puts the warm ratio near
// 0.4 and the no-cache ratio near 1.0; 0.8 sits in the empty band between
// them. Both sides of the ratio scale with the machine, so this is a property
// of the cache, not of the hardware.
const maxWarmRatio = 0.8

// TestPerformanceBudgets measures baseline and cache-warm ("daily
// incremental") scans of the same isolated fixture home and prints the numbers
// for eyeball comparison against §12 of the design.
//
// The only assertion is the one budget that does not depend on the machine:
// over an unchanged fixture the cache-warm scan must be faster than the cold
// baseline by the margin in maxWarmRatio. That is a property of the content
// cache; the absolute seconds are a property of the hardware and are
// reported, never asserted.
func TestPerformanceBudgets(t *testing.T) {
	home := copyOfficialFixtureHome(t)
	normalizeEvidenceFixtureModes(t, home)
	bulkBytes := writePerfBulkPlugin(t, home)
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")

	baselineStart := time.Now()
	first := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-0000000000b1",
	})
	baselineElapsed := time.Since(baselineStart)

	incrementalStart := time.Now()
	second := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-0000000000b2",
	})
	incrementalElapsed := time.Since(incrementalStart)

	// syscall.Getrusage(RUSAGE_SELF) reports ru_maxrss, the high-water mark of
	// the whole test process since it started. On Darwin that value is bytes.
	// Limitations: it is process-wide (test binary, Go runtime and SQLite are
	// included, not just the scan), it is monotonic and cannot be reset, so
	// the two runs cannot be attributed separately, and it is a peak, not an
	// average. It is still the closest single number to §12's "at most 500 MB
	// memory" that costs no dependency.
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	peakRSS := int64(usage.Maxrss)

	t.Logf("fixture: official home + %d synthetic payload files (%s)", perfBulkFiles, humanBytes(bulkBytes))
	t.Logf("baseline (cold cache):    %v   [§12 budget: 10m]", baselineElapsed)
	t.Logf("incremental (warm cache): %v   [§12 budget: 60s]", incrementalElapsed)
	ratio := float64(incrementalElapsed) / float64(baselineElapsed)
	t.Logf("incremental/baseline ratio: %.3f   [must be < %.2f]", ratio, maxWarmRatio)
	t.Logf("peak process RSS: %s   [§12 budget: 500MB]", humanBytes(peakRSS))
	t.Logf("evidence cache, baseline:    %v", evidenceCacheCounts(first.Inventory))
	t.Logf("evidence cache, incremental: %v", evidenceCacheCounts(second.Inventory))

	if ratio >= maxWarmRatio {
		t.Fatalf("cache-warm scan was not meaningfully faster than the cold baseline: incremental=%v baseline=%v ratio=%.3f want <%.2f", incrementalElapsed, baselineElapsed, ratio, maxWarmRatio)
	}
}

// writePerfBulkPlugin adds one closed-catalog Codex plugin whose payload tree
// is large enough that the content cache has real work to skip, and returns
// the number of payload bytes written.
func writePerfBulkPlugin(t *testing.T, home string) int64 {
	t.Helper()
	pluginDir := filepath.Join(home, ".codex", "plugins", "perf-bulk")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"perf-bulk","version":"1.0.0"}`)
	for index := range perfBulkFiles {
		payload := make([]byte, perfBulkFileBytes)
		for offset := range payload {
			payload[offset] = byte(index + offset)
		}
		name := filepath.Join(pluginDir, fmt.Sprintf("payload-%03d.js", index))
		if err := os.WriteFile(name, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return int64(perfBulkFiles) * perfBulkFileBytes
}

// evidenceCacheCounts summarizes the per-record cache outcome so a failing run
// shows immediately whether the cache was warm at all.
func evidenceCacheCounts(inventory model.Inventory) map[string]int {
	counts := map[string]int{}
	for _, record := range inventory.Evidence {
		counts[record.Metadata[model.MetadataCache]]++
	}
	return counts
}

func humanBytes(value int64) string {
	return fmt.Sprintf("%.1fMB", float64(value)/(1<<20))
}
