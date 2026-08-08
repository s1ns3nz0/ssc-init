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
	"crypto/sha256"
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

// A scan costs F+H: F is fixed overhead both runs pay (directory walks, per
// target validation, SQLite, process setup) and H is the content hashing the
// warm run skips, so the best ratio a perfect cache can reach is F/(F+H). That
// is a property of the host, not of the cache: F and H scale with different
// things. A payload sweep on this machine measured a warm side of 37-50ms
// across a 512x payload range (pure F) while only the cold side grew with the
// bytes, and under `-race` F alone inflates from ~44ms to ~718ms — F/(F+H)
// lands at ~0.96 with a demonstrably warm cache (`map[:23 hit:4]`). So a fixed
// ratio threshold is fitted to one payload on one host, not structural.
//
// Instead the harness estimates H directly (SHA-256 throughput x payload
// bytes), asserts only when H is a large enough share of the cold scan and of
// run-to-run noise for the cache to be visible at all, and derives the
// threshold from that share. A bare "strictly faster" comparison is not enough
// either: with the second run's reads served from the OS page cache, a
// deliberately cold second scan still measured 0.955-0.980 here, so `<1` would
// have passed with the cache doing nothing.
const (
	// minHashingShare is the smallest share of the cold scan that hashing must
	// account for before the warm/cold ratio can resolve the cache at all.
	minHashingShare = 0.25
	// minNoiseMargin is how many times the run-to-run spread of warm scans the
	// estimated hashing cost must exceed before the ratio means anything.
	minNoiseMargin = 4
	// minDeliveredHashing is the share of the estimated hashing cost the warm
	// scan must actually save. Half leaves room for the estimate being a lower
	// bound (it excludes the read I/O the cache also skips) and for noise.
	minDeliveredHashing = 0.5
)

// TestPerformanceBudgets measures baseline and cache-warm ("daily
// incremental") scans of the same isolated fixture home and reports the
// numbers.
//
// The fixture is a synthetic home some orders of magnitude smaller than the
// workload §12 of the design budgets, so these numbers are not a measurement
// of those budgets and satisfying them here says nothing about satisfying
// them there. The one thing this fixture can show is that the content cache
// saves the hashing work on an unchanged tree — and only when the measurement
// is sharp enough to see that saving, which is checked before asserting.
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

	// A second warm scan costs one more cheap run and is the only way to know
	// how much of the warm/cold gap is signal and how much is jitter.
	repeatStart := time.Now()
	third := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-0000000000b3",
	})
	repeatElapsed := time.Since(repeatStart)
	warmElapsed := max(incrementalElapsed, repeatElapsed)
	warmNoise := warmElapsed - min(incrementalElapsed, repeatElapsed)

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

	hashingCost := sha256Cost(bulkBytes)
	hashingShare := float64(hashingCost) / float64(baselineElapsed)
	ratio := float64(warmElapsed) / float64(baselineElapsed)
	maxWarmRatio := 1 - hashingShare*minDeliveredHashing

	t.Logf("fixture: official home + %d synthetic payload files (%s); orders of magnitude smaller than the §12 workload, so §12's 10m/60s/500MB budgets are NOT measured here", perfBulkFiles, humanBytes(bulkBytes))
	t.Logf("baseline (cold cache):    %v", baselineElapsed)
	t.Logf("incremental (warm cache): %v (repeat %v, spread %v)", incrementalElapsed, repeatElapsed, warmNoise)
	t.Logf("warm/cold ratio: %.3f", ratio)
	t.Logf("estimated hashing cost: %v (%.1f%% of the cold scan)", hashingCost, hashingShare*100)
	t.Logf("peak process RSS: %s (whole test process, reported only)", humanBytes(peakRSS))
	t.Logf("evidence cache, baseline:    %v", evidenceCacheCounts(first.Inventory))
	t.Logf("evidence cache, incremental: %v", evidenceCacheCounts(second.Inventory))
	t.Logf("evidence cache, repeat:      %v", evidenceCacheCounts(third.Inventory))

	// Both gates are cache-independent: they are computed from the cold scan
	// and from SHA-256 throughput, never from the warm/cold gap the assertion
	// is about. A dead cache therefore cannot excuse itself by shrinking that
	// gap — it still gets asserted on.
	switch {
	case hashingShare < minHashingShare:
		t.Skipf("measurement cannot discriminate: hashing is only %.1f%% of the cold scan (want >=%.0f%%), so fixed per-target overhead swamps whatever the cache saves; grow the payload or run without -race", hashingShare*100, minHashingShare*100)
	case float64(hashingCost) < minNoiseMargin*float64(warmNoise):
		t.Skipf("measurement cannot discriminate: warm-scan spread %v is within %dx of the %v the cache can save; the host is too noisy to time this", warmNoise, minNoiseMargin, hashingCost)
	}

	if ratio >= maxWarmRatio {
		t.Fatalf("cache-warm scan did not save the hashing it skips: warm=%v baseline=%v ratio=%.3f want <%.3f (cache should save >=%.0f%% of the %v hashing cost)", warmElapsed, baselineElapsed, ratio, maxWarmRatio, minDeliveredHashing*100, hashingCost)
	}
}

// sha256Cost measures this host's SHA-256 throughput over the payload size, a
// cache-independent lower bound on the work a warm scan skips (it excludes the
// read I/O the cache also skips).
func sha256Cost(bytes int64) time.Duration {
	block := make([]byte, perfBulkFileBytes)
	digest := sha256.New()
	start := time.Now()
	for written := int64(0); written < bytes; written += int64(len(block)) {
		digest.Write(block)
	}
	digest.Sum(nil)
	return time.Since(start)
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
