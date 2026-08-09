package bundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLayoutUsesClosedFamilyAndSequenceComponents(t *testing.T) {
	home := t.TempDir()
	layout, err := LayoutFor(home, FamilyTI)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(home, "Library", "Application Support", "SSC Init", "bundles", "ti")
	if layout.Root != wantRoot || layout.VersionDir(7) != filepath.Join(wantRoot, "versions", "7") {
		t.Fatalf("layout=%+v", layout)
	}
	for _, family := range []Family{"", "../ti", "TI", "policy/other"} {
		if _, err := LayoutFor(home, family); err != ErrLayout {
			t.Fatalf("family=%q err=%v", family, err)
		}
	}
}

func TestInitializeLayoutRejectsSymlinkedFamilyRoot(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	bundles := filepath.Join(home, "Library", "Application Support", "SSC Init", "bundles")
	if err := os.MkdirAll(bundles, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(bundles, "ti")); err != nil {
		t.Fatal(err)
	}
	layout, err := LayoutFor(home, FamilyTI)
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.Initialize(); err != ErrLayout {
		t.Fatalf("initialize err=%v", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target touched: entries=%v err=%v", entries, err)
	}
}
