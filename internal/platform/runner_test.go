package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecRunnerLimitsOutput(t *testing.T) {
	r := ExecRunner{Timeout: time.Second, MaxOutputBytes: 4}

	got, err := r.Run(context.Background(), "/bin/echo", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if got.Stdout != "1234" || !got.Truncated {
		t.Fatalf("got=%+v", got)
	}
}

func TestExecRunnerUsesSuppliedAbsolutePathWithoutPATHReresolution(t *testing.T) {
	spoofBin := t.TempDir()
	trustedBin := t.TempDir()
	spoof := filepath.Join(spoofBin, "probe-tool")
	trusted := filepath.Join(trustedBin, "probe-tool")
	if err := os.WriteFile(spoof, []byte("#!/bin/sh\nprintf spoof\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nprintf inspected\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", spoofBin)

	got, err := (ExecRunner{Timeout: 5 * time.Second, MaxOutputBytes: 1024}).Run(context.Background(), trusted)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stdout != "inspected" || got.ExitCode != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func TestExecRunnerReturnsTypedTimeoutError(t *testing.T) {
	r := ExecRunner{Timeout: 10 * time.Millisecond, MaxOutputBytes: 4}

	_, err := r.Run(context.Background(), "/bin/sleep", "1")
	if err == nil {
		t.Fatal("expected timeout error")
	}

	var timeoutErr *TimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("error=%T %[1]v", err)
	}
}
