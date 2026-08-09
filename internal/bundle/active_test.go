package bundle

import (
	"context"
	"testing"
	"time"
)

func TestActiveReverifiesAndReturnsTypedPayloadWithFreshness(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "active fixture")
	manager := testManager(t, home, publicKey)
	bundlePath, signaturePath := writeSignedBundleFixture(t, validTIBundleBytes("ti-key"), privateKey)
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC) }
	active, err := manager.Active(context.Background())
	if err != nil || active.Status.Freshness != FreshnessStale || active.Verified.Envelope.TI == nil || active.Verified.Envelope.Policy != nil {
		t.Fatalf("active=%+v err=%v", active, err)
	}
}

func TestActiveMissingIsExplicitAndCreatesNoState(t *testing.T) {
	home := t.TempDir()
	layout, _ := LayoutFor(home, FamilyTI)
	manager := Manager{Layout: layout, Family: FamilyTI, Now: testBundleNow}
	if _, err := manager.Active(context.Background()); err != ErrActiveUnavailable {
		t.Fatalf("active err=%v", err)
	}
}
