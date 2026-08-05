package platform

import (
	"context"
	"errors"
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
