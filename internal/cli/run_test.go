package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"version", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}

	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["product"] != "SSC Init" || got["command"] != "ssc-init" {
		t.Fatalf("got=%v", got)
	}
}

func TestRunVersionReturnsErrorWhenOutputFails(t *testing.T) {
	var errOut bytes.Buffer
	code := Run(context.Background(), []string{"version", "--json"}, failingWriter{err: errors.New("disk full")}, &errOut)
	if code == 0 {
		t.Fatal("code=0")
	}
	if !strings.Contains(errOut.String(), "failed to write version output") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"wat"}, &out, &errOut); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(errOut.String(), "unknown command: wat") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}
