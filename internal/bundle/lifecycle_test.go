package bundle

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestManagerStagesReverifiesAndActivatesBundle(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "lifecycle fixture")
	raw := validTIBundleBytes("ti-key")
	bundlePath, signaturePath := writeSignedBundleFixture(t, raw, privateKey)
	manager := testManager(t, home, publicKey)

	verified, err := manager.Install(context.Background(), bundlePath, signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Envelope.Sequence != 7 {
		t.Fatalf("verified=%+v", verified)
	}
	layout, _ := LayoutFor(home, FamilyTI)
	if got := readLifecycleFile(t, layout.CurrentFile); got != "7" {
		t.Fatalf("current=%q", got)
	}
	stored, err := os.ReadFile(filepath.Join(layout.VersionDir(7), "bundle.json"))
	if err != nil || string(stored) != string(raw) {
		t.Fatalf("stored bundle mismatch: err=%v", err)
	}
	if got := readLifecycleFile(t, filepath.Join(layout.VersionDir(7), "bundle.sig")); got == "" {
		t.Fatal("signature was not stored")
	}
}

func TestManagerFailurePreservesLastKnownGoodAndLeavesNoStage(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "failure fixture")
	manager := testManager(t, home, publicKey)
	raw := validTIBundleBytes("ti-key")
	bundlePath, signaturePath := writeSignedBundleFixture(t, raw, privateKey)
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 1
	badBundle, badSignature := writeSignedBundleFixture(t, tampered, privateKey)
	if _, err := manager.Install(context.Background(), badBundle, badSignature); err != ErrInstall {
		t.Fatalf("tampered install err=%v", err)
	}
	layout, _ := LayoutFor(home, FamilyTI)
	if got := readLifecycleFile(t, layout.CurrentFile); got != "7" {
		t.Fatalf("current changed after failure: %q", got)
	}
	entries, err := os.ReadDir(layout.StagingDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging remnants=%v err=%v", entries, err)
	}
}

func TestManagerRejectsSymlinkSourcesAndCancellationWithoutState(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "boundary fixture")
	manager := testManager(t, home, publicKey)
	raw := validTIBundleBytes("ti-key")
	bundlePath, signaturePath := writeSignedBundleFixture(t, raw, privateKey)
	linkedBundle := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.Symlink(bundlePath, linkedBundle); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Install(context.Background(), linkedBundle, signaturePath); err != ErrInstall {
		t.Fatalf("symlink install err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Install(ctx, bundlePath, signaturePath); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled install err=%v", err)
	}
	layout, _ := LayoutFor(home, FamilyTI)
	if _, err := os.Stat(layout.Root); !os.IsNotExist(err) {
		t.Fatalf("failed installs created state: err=%v", err)
	}
}

func TestManagerRejectsSequenceRollbackAndPreservesHighWaterAcrossRollback(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "rollback fixture")
	manager := testManager(t, home, publicKey)
	for _, sequence := range []uint64{7, 8} {
		raw := validTIBundleSequenceBytes("ti-key", sequence)
		bundlePath, signaturePath := writeSignedBundleFixture(t, raw, privateKey)
		if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
			t.Fatalf("install sequence %d: %v", sequence, err)
		}
	}
	layout, _ := LayoutFor(home, FamilyTI)
	if got := readLifecycleFile(t, layout.HighWaterFile); got != "8" {
		t.Fatalf("high water=%q", got)
	}
	older, olderSignature := writeSignedBundleFixture(t, validTIBundleSequenceBytes("ti-key", 6), privateKey)
	if _, err := manager.Install(context.Background(), older, olderSignature); err != ErrRollback {
		t.Fatalf("downgrade install err=%v", err)
	}
	if got := readLifecycleFile(t, layout.CurrentFile); got != "8" {
		t.Fatalf("downgrade changed current=%q", got)
	}
	if err := manager.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readLifecycleFile(t, layout.CurrentFile); got != "7" {
		t.Fatalf("rollback current=%q", got)
	}
	if got := readLifecycleFile(t, layout.HighWaterFile); got != "8" {
		t.Fatalf("rollback lowered high water=%q", got)
	}
}

func TestManagerRejectsDifferentBytesAtAcceptedSequence(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "sequence collision fixture")
	manager := testManager(t, home, publicKey)
	raw := validTIBundleBytes("ti-key")
	bundlePath, signaturePath := writeSignedBundleFixture(t, raw, privateKey)
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	changed := []byte(strings.Replace(string(raw), `"version":"2026.08.10"`, `"version":"2026.08.10-repacked"`, 1))
	changedPath, changedSignature := writeSignedBundleFixture(t, changed, privateKey)
	if _, err := manager.Install(context.Background(), changedPath, changedSignature); err != ErrRollback {
		t.Fatalf("sequence collision err=%v", err)
	}
	layout, _ := LayoutFor(home, FamilyTI)
	stored, err := os.ReadFile(filepath.Join(layout.VersionDir(7), "bundle.json"))
	if err != nil || string(stored) != string(raw) {
		t.Fatalf("accepted sequence was replaced: err=%v", err)
	}
}

func TestManagerRefusesConcurrentWriterAndRemovesPlantedPointerSymlink(t *testing.T) {
	home := t.TempDir()
	publicKey, privateKey := deterministicKey(t, "concurrency fixture")
	manager := testManager(t, home, publicKey)
	raw := validTIBundleBytes("ti-key")
	bundlePath, signaturePath := writeSignedBundleFixture(t, raw, privateKey)
	if err := manager.Layout.Initialize(); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(manager.Layout.Root, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatalf("lock err=%v", err)
	}
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != ErrInstall {
		t.Fatalf("competing install err=%v", err)
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
	outside := filepath.Join(t.TempDir(), "must-not-change")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(manager.Layout.Root, "current.tmp")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "original" {
		t.Fatalf("planted pointer target changed: %q err=%v", got, err)
	}
}

func testManager(t *testing.T, home string, publicKey ed25519.PublicKey) Manager {
	t.Helper()
	layout, err := LayoutFor(home, FamilyTI)
	if err != nil {
		t.Fatal(err)
	}
	return Manager{Layout: layout, Family: FamilyTI, Verifier: Verifier{Keys: KeyRegistry{FamilyTI: {"ti-key": publicKey}}}, Now: testBundleNow}
}

func writeSignedBundleFixture(t *testing.T, raw []byte, privateKey ed25519.PrivateKey) (string, string) {
	t.Helper()
	directory := t.TempDir()
	bundlePath, signaturePath := filepath.Join(directory, "bundle.json"), filepath.Join(directory, "bundle.sig")
	if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, ed25519.Sign(privateKey, raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundlePath, signaturePath
}

func readLifecycleFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}
