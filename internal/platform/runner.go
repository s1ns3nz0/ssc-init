package platform

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// CommandResult is the bounded output from a completed command.
type CommandResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// Runner executes a command without a shell.
type Runner interface {
	Run(context.Context, string, ...string) (CommandResult, error)
}

// ExecRunner executes host commands with a time and output bound.
type ExecRunner struct {
	Timeout        time.Duration
	MaxOutputBytes int
}

// TimeoutError reports a command that exceeded its execution deadline.
type TimeoutError struct {
	Command string
	Timeout time.Duration
}

func (e *TimeoutError) Error() string {
	if e.Timeout > 0 {
		return fmt.Sprintf("command %q timed out after %s", e.Command, e.Timeout)
	}
	return fmt.Sprintf("command %q timed out", e.Command)
}

func (e *TimeoutError) Unwrap() error {
	return context.DeadlineExceeded
}

// Run executes command directly with args, without shell interpolation.
func (r ExecRunner) Run(ctx context.Context, command string, args ...string) (CommandResult, error) {
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	stdout := newLimitedOutput(r.MaxOutputBytes)
	stderr := newLimitedOutput(r.MaxOutputBytes)
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	result := CommandResult{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  -1,
		Truncated: stdout.Truncated() || stderr.Truncated(),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return result, &TimeoutError{Command: command, Timeout: r.Timeout}
	}
	return result, err
}

type limitedOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func newLimitedOutput(max int) *limitedOutput {
	if max < 0 {
		max = 0
	}
	return &limitedOutput{max: max}
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	remaining := w.max - w.buf.Len()
	if remaining <= 0 {
		if len(p) > 0 {
			w.truncated = true
		}
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = w.buf.Write(p[:remaining])
		w.truncated = true
		return len(p), nil
	}
	_, _ = w.buf.Write(p)
	return len(p), nil
}

func (w *limitedOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *limitedOutput) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}
