package platform

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutableInspectorCapturesDirectExecutableWithoutSerializingExecutionIdentity(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	executable := filepath.Join(bin, "demo")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := []byte("#!/bin/sh\necho demo\n")
	if err := os.WriteFile(executable, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	inspector := NewExecutableInspector(16, 64<<20)
	evidence, err := inspector.Inspect(context.Background(), home, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Command != "demo" || evidence.Path != executable || evidence.LocationRef != "$HOME/bin/demo" {
		t.Fatalf("evidence=%+v", evidence)
	}
	if evidence.SHA256 != "a5a301c60af0fd8cd3d77a140c73dd78dc87848025d499d5afcc1f2f7327572f" || evidence.Mode&0o111 == 0 {
		t.Fatalf("evidence=%+v", evidence)
	}
	if evidence.Identity.Size != int64(len(contents)) || evidence.Identity.Inode == 0 {
		t.Fatalf("identity=%+v", evidence.Identity)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), executable) || strings.Contains(string(encoded), "Identity") || strings.Contains(string(encoded), "inode") {
		t.Fatalf("execution identity serialized: %s", encoded)
	}
}

func TestExecutableInspectorRejectsUnsafeTargetsAndBounds(t *testing.T) {
	t.Run("symlink loop", func(t *testing.T) {
		directory := t.TempDir()
		first := filepath.Join(directory, "first")
		second := filepath.Join(directory, "second")
		if err := os.Symlink(second, first); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(first, second); err != nil {
			t.Fatal(err)
		}
		inspector := NewExecutableInspector(16, 64<<20).(*boundedExecutableInspector)
		if _, _, _, err := inspector.resolve(context.Background(), directory, first); err == nil {
			t.Fatal("expected symlink loop rejection")
		}
	})

	t.Run("symlink chain limit", func(t *testing.T) {
		directory := t.TempDir()
		final := filepath.Join(directory, "final")
		if err := os.WriteFile(final, []byte("ok"), 0o755); err != nil {
			t.Fatal(err)
		}
		current := final
		for index := 16; index >= 0; index-- {
			link := filepath.Join(directory, "link-"+string(rune('a'+index)))
			if err := os.Symlink(filepath.Base(current), link); err != nil {
				t.Fatal(err)
			}
			current = link
		}
		inspector := NewExecutableInspector(16, 64<<20).(*boundedExecutableInspector)
		if _, _, _, err := inspector.resolve(context.Background(), directory, current); err == nil {
			t.Fatal("expected chain-limit rejection")
		}
	})

	for _, testCase := range []struct {
		name, contents string
		mode           os.FileMode
		maxBytes       int64
	}{
		{name: "non regular", mode: os.ModeDir | 0o755, maxBytes: 64 << 20},
		{name: "non executable", contents: "data", mode: 0o644, maxBytes: 64 << 20},
		{name: "oversized", contents: "12345", mode: 0o755, maxBytes: 4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "tool")
			if testCase.mode&os.ModeDir != 0 {
				if err := os.Mkdir(path, testCase.mode.Perm()); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(testCase.contents), testCase.mode); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory)
			if _, err := NewExecutableInspector(16, testCase.maxBytes).Inspect(context.Background(), directory, "tool"); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestExecutableInspectorHidesOutsideHomeChainReferences(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()
	real := filepath.Join(external, "real")
	link := filepath.Join(external, "tool")
	if err := os.WriteFile(real, []byte("outside"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", external)

	evidence, err := NewExecutableInspector(16, 64<<20).Inspect(context.Background(), home, "tool")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(evidence.LocationRef, "external-executable:2/path-sha256:") || len(evidence.SymlinkRefs) != 1 || !strings.HasPrefix(evidence.SymlinkRefs[0], "external-executable:1/path-sha256:") {
		t.Fatalf("evidence=%+v", evidence)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), external) || strings.Contains(string(encoded), real) || strings.Contains(string(encoded), link) {
		t.Fatalf("outside path leaked: %s", encoded)
	}
}

func TestExecutableInspectorDetectsInspectionAndPostRunReplacement(t *testing.T) {
	t.Run("replacement after open", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "tool")
		if err := os.WriteFile(path, []byte("original"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory)
		inspector := NewExecutableInspector(16, 64<<20).(*boundedExecutableInspector)
		inspector.afterOpen = func(string) {
			replacement := filepath.Join(directory, "replacement")
			if err := os.WriteFile(replacement, []byte("replaced"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := inspector.Inspect(context.Background(), directory, "tool"); !errors.Is(err, errExecutableChanged) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("replacement after inspection", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "tool")
		if err := os.WriteFile(path, []byte("original"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", directory)
		inspector := NewExecutableInspector(16, 64<<20)
		evidence, err := inspector.Inspect(context.Background(), directory, "tool")
		if err != nil {
			t.Fatal(err)
		}
		replacement := filepath.Join(directory, "replacement")
		if err := os.WriteFile(replacement, []byte("replaced"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		if err := inspector.Verify(evidence); !errors.Is(err, errExecutableChanged) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestExecutableInspectorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewExecutableInspector(16, 64<<20).Inspect(ctx, t.TempDir(), "tool")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestExecutableInspectorResolvesRelativeTwoLinkChainWithSafeReferences(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	real := filepath.Join(home, "libexec", "real-tool")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libexec/real-tool", filepath.Join(home, "link-two")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../link-two", filepath.Join(bin, "tool")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	evidence, err := NewExecutableInspector(16, 64<<20).Inspect(context.Background(), home, "tool")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Path != real || evidence.LocationRef != "$HOME/libexec/real-tool" {
		t.Fatalf("evidence=%+v", evidence)
	}
	wantRefs := []string{"$HOME/bin/tool", "$HOME/link-two"}
	if len(evidence.SymlinkRefs) != len(wantRefs) {
		t.Fatalf("refs=%q", evidence.SymlinkRefs)
	}
	for index := range wantRefs {
		if evidence.SymlinkRefs[index] != wantRefs[index] {
			t.Fatalf("refs=%q want=%q", evidence.SymlinkRefs, wantRefs)
		}
	}
}
