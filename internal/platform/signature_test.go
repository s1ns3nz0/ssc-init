package platform

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestMacOSSignatureInspectorMapsClosedFacts(t *testing.T) {
	path := "/Applications/Demo.app/Contents/MacOS/demo"
	tests := []struct {
		name    string
		results []signatureRun
		want    model.Signature
		wantErr bool
	}{
		{name: "valid", results: []signatureRun{{result: CommandResult{ExitCode: 0}}, {result: CommandResult{ExitCode: 0, Stderr: "Identifier=dev.example.demo\nTeamIdentifier=ABCDE12345\nAuthority=private marker\n"}}}, want: model.Signature{Status: model.SignatureValid, Identifier: "dev.example.demo", TeamID: "ABCDE12345"}},
		{name: "unsigned", results: []signatureRun{{result: CommandResult{ExitCode: 1, Stderr: path + ": code object is not signed at all\n"}, err: errors.New("exit status 1")}}, want: model.Signature{Status: model.SignatureUnsigned}},
		{name: "invalid", results: []signatureRun{{result: CommandResult{ExitCode: 1, Stderr: path + ": invalid signature (code or signature have been modified)\n"}, err: errors.New("exit status 1")}}, want: model.Signature{Status: model.SignatureInvalid}},
		{name: "truncated", results: []signatureRun{{result: CommandResult{ExitCode: 0, Truncated: true}}}, want: model.Signature{Status: model.SignatureUnavailable}, wantErr: true},
		{name: "timeout", results: []signatureRun{{result: CommandResult{ExitCode: -1}, err: &TimeoutError{Command: "/usr/bin/codesign"}}}, want: model.Signature{Status: model.SignatureUnavailable}, wantErr: true},
		{name: "malformed identity", results: []signatureRun{{result: CommandResult{ExitCode: 0}}, {result: CommandResult{ExitCode: 0, Stderr: "Identifier=bad/private\nTeamIdentifier=ABCDE12345\n"}}}, want: model.Signature{Status: model.SignatureUnavailable}, wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			runner := &signatureRunner{runs: testCase.results}
			verifier := &signatureVerifier{}
			got, err := newSignatureInspector("darwin", runner).Inspect(context.Background(), ExecutableEvidence{Path: path}, verifier)
			if (err != nil) != testCase.wantErr || !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("signature=%+v err=%v want=%+v wantErr=%v", got, err, testCase.want, testCase.wantErr)
			}
			if !testCase.wantErr && testCase.want.Status == model.SignatureValid && verifier.calls != 2 {
				t.Fatalf("verification calls=%d", verifier.calls)
			}
			for _, call := range runner.calls {
				if call.command != "/usr/bin/codesign" || call.args[len(call.args)-1] != path {
					t.Fatalf("call=%+v", call)
				}
			}
		})
	}
}

func TestSignatureInspectorUnsupportedPlatformInvokesNothing(t *testing.T) {
	runner := &signatureRunner{}
	verifier := &signatureVerifier{}
	got, err := newSignatureInspector("linux", runner).Inspect(context.Background(), ExecutableEvidence{Path: "/bin/demo"}, verifier)
	if err != nil || got.Status != model.SignatureUnsupported || len(runner.calls) != 0 || verifier.calls != 0 {
		t.Fatalf("signature=%+v err=%v calls=%+v verifies=%d", got, err, runner.calls, verifier.calls)
	}
}

func TestSignatureInspectorFailsClosedOnCancellationAndReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &signatureRunner{}
	got, err := newSignatureInspector("darwin", runner).Inspect(ctx, ExecutableEvidence{Path: "/bin/demo"}, &signatureVerifier{})
	if !errors.Is(err, context.Canceled) || got.Status != model.SignatureUnavailable || len(runner.calls) != 0 {
		t.Fatalf("signature=%+v err=%v calls=%+v", got, err, runner.calls)
	}

	verifier := &signatureVerifier{failAt: 2}
	runner = &signatureRunner{runs: []signatureRun{{result: CommandResult{ExitCode: 0}}, {result: CommandResult{ExitCode: 0, Stderr: "Identifier=dev.example.demo\nTeamIdentifier=ABCDE12345\n"}}}}
	got, err = newSignatureInspector("darwin", runner).Inspect(context.Background(), ExecutableEvidence{Path: "/bin/demo"}, verifier)
	if err == nil || got.Status != model.SignatureUnavailable || verifier.calls != 2 {
		t.Fatalf("signature=%+v err=%v verifies=%d", got, err, verifier.calls)
	}
}

type signatureRun struct {
	result CommandResult
	err    error
}

type signatureCall struct {
	command string
	args    []string
}

type signatureRunner struct {
	runs  []signatureRun
	calls []signatureCall
}

func (r *signatureRunner) Run(_ context.Context, command string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, signatureCall{command: command, args: append([]string(nil), args...)})
	if len(r.runs) == 0 {
		return CommandResult{}, errors.New("unexpected call")
	}
	run := r.runs[0]
	r.runs = r.runs[1:]
	return run.result, run.err
}

type signatureVerifier struct {
	calls  int
	failAt int
}

func (v *signatureVerifier) Verify(ExecutableEvidence) error {
	v.calls++
	if v.calls == v.failAt {
		return errors.New("executable replaced")
	}
	return nil
}
