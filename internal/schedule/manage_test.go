package schedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

type runnerCall struct {
	command string
	args    []string
}
type fakeRunner struct {
	mu            sync.Mutex
	calls         []runnerCall
	loaded        bool
	failBootstrap bool
	failBootout   bool
}

func (f *fakeRunner) Run(_ context.Context, command string, args ...string) (platform.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, runnerCall{command: command, args: append([]string(nil), args...)})
	if len(args) > 0 && args[0] == "print" {
		if f.loaded {
			return platform.CommandResult{ExitCode: 0}, nil
		}
		return platform.CommandResult{ExitCode: 113}, errors.New("not loaded")
	}
	if len(args) > 0 && args[0] == "bootstrap" {
		if f.failBootstrap {
			return platform.CommandResult{ExitCode: 5}, errors.New("bootstrap failed")
		}
		f.loaded = true
		return platform.CommandResult{ExitCode: 0}, nil
	}
	if len(args) > 0 && args[0] == "bootout" {
		if f.failBootout {
			return platform.CommandResult{ExitCode: 5}, errors.New("bootout failed")
		}
		f.loaded = false
		return platform.CommandResult{ExitCode: 0}, nil
	}
	return platform.CommandResult{ExitCode: 1}, errors.New("unexpected")
}

func (f *fakeRunner) state() (bool, []runnerCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded, append([]runnerCall(nil), f.calls...)
}

func TestInstallIsAtomicAndIdempotentAcrossAdapters(t *testing.T) {
	manager, runner := managedScheduleFixture(t)
	first, err := manager.Install(context.Background())
	loaded, _ := runner.state()
	if err != nil || first.Status != StatusInstalled || !loaded {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	plist := manager.plistPath()
	info, err := os.Lstat(plist)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("plist=%v err=%v", info, err)
	}
	before, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Install(context.Background())
	after, readErr := os.ReadFile(plist)
	if err != nil || readErr != nil || second.Status != StatusAlreadyInstalled || !reflect.DeepEqual(before, after) {
		t.Fatalf("second=%+v err=%v readErr=%v", second, err, readErr)
	}
	_, calls := runner.state()
	if len(calls) != 3 {
		t.Fatalf("calls=%+v", calls)
	}
}

func TestInstallRejectsDifferentOrSymlinkedManagedPlist(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		manager, runner := managedScheduleFixture(t)
		path := manager.plistPath()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if symlink {
			target := filepath.Join(manager.Home, "target")
			if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Install(context.Background()); !errors.Is(err, ErrUnsafeScheduleState) {
			t.Fatalf("symlink=%v err=%v", symlink, err)
		}
		_, calls := runner.state()
		if len(calls) != 0 {
			t.Fatalf("runner called: %+v", calls)
		}
	}
}

func TestRemoveBootsOutExactJobAndIsIdempotent(t *testing.T) {
	manager, runner := managedScheduleFixture(t)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	removed, err := manager.Remove(context.Background())
	loaded, _ := runner.state()
	if err != nil || removed.Status != StatusRemoved || loaded {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
	if _, err := os.Lstat(manager.plistPath()); !os.IsNotExist(err) {
		t.Fatalf("plist remains: %v", err)
	}
	again, err := manager.Remove(context.Background())
	if err != nil || again.Status != StatusNotInstalled {
		t.Fatalf("again=%+v err=%v", again, err)
	}
}

func TestConcurrentInstallsSerializeAndRemainIdempotent(t *testing.T) {
	manager, runner := managedScheduleFixture(t)
	results := make(chan Result, 2)
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			ready.Done()
			<-start
			result, err := manager.Install(context.Background())
			results <- result
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	seen := map[Status]int{}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		seen[(<-results).Status]++
	}
	if seen[StatusInstalled] != 1 || seen[StatusAlreadyInstalled] != 1 {
		t.Fatalf("statuses=%v", seen)
	}
	loaded, calls := runner.state()
	if !loaded || len(calls) != 3 {
		t.Fatalf("loaded=%v calls=%+v", loaded, calls)
	}
}

func TestBootstrapFailureRollsBackNewPlist(t *testing.T) {
	manager, runner := managedScheduleFixture(t)
	runner.failBootstrap = true
	if _, err := manager.Install(context.Background()); !errors.Is(err, ErrScheduleCommand) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Lstat(manager.plistPath()); !os.IsNotExist(err) {
		t.Fatalf("plist remains after rollback: %v", err)
	}
}

func TestBootoutFailurePreservesManagedPlist(t *testing.T) {
	manager, runner := managedScheduleFixture(t)
	if _, err := manager.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.failBootout = true
	runner.mu.Unlock()
	if _, err := manager.Remove(context.Background()); !errors.Is(err, ErrScheduleCommand) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Lstat(manager.plistPath()); err != nil {
		t.Fatalf("managed plist was removed: %v", err)
	}
}

func managedScheduleFixture(t *testing.T) (Manager, *fakeRunner) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(home, "Library", "Application Support", "SSC Init", "core", "versions", "v1.0.0", "ssc-init")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	return Manager{Home: home, Executable: executable, UID: 501, Runner: runner}, runner
}
