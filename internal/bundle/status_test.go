package bundle

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagerReportsMissingFreshStaleAndExpiredWithoutChangingState(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "status fixture")
	manager := testManager(t, home, publicKey)
	status, err := manager.Status(context.Background())
	if err != nil || status.Freshness != FreshnessMissing {
		t.Fatalf("missing status=%+v err=%v", status, err)
	}
	layout, _ := LayoutFor(home, FamilyTI)
	if _, err := os.Stat(layout.Root); !os.IsNotExist(err) {
		t.Fatalf("status created state: err=%v", err)
	}
	bundlePath, signaturePath := writeSignedBundleFixture(t, validTIBundleBytes("ti-key"), privateKey)
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		now  time.Time
		want Freshness
	}{
		{time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), FreshnessFresh},
		{time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC), FreshnessStale},
		{time.Date(2026, 8, 28, 0, 0, 1, 0, time.UTC), FreshnessExpired},
	} {
		manager.Now = func() time.Time { return testCase.now }
		status, err := manager.Status(context.Background())
		if err != nil || status.Freshness != testCase.want || status.Sequence != 7 || status.Family != FamilyTI {
			t.Fatalf("now=%s status=%+v err=%v", testCase.now, status, err)
		}
		if len(status.Digest) != 64 || status.KeyID != "ti-key" || status.Records != 0 {
			t.Fatalf("verified metadata missing: %+v", status)
		}
	}
}

func TestManagerReportsUnavailableForTamperedActiveBundle(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "status tamper fixture")
	manager := testManager(t, home, publicKey)
	bundlePath, signaturePath := writeSignedBundleFixture(t, validTIBundleBytes("ti-key"), privateKey)
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	layout, _ := LayoutFor(home, FamilyTI)
	if err := os.WriteFile(filepath.Join(layout.VersionDir(7), "bundle.sig"), make([]byte, ed25519.SignatureSize), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(context.Background())
	if err != nil || status.Freshness != FreshnessUnavailable || status.Sequence != 0 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}
