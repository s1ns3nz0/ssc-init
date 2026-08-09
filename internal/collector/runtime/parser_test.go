package runtime

import (
	"strings"
	"testing"
)

func TestRuntimeParsersRetainOnlyApprovedFacts(t *testing.T) {
	processes, err := parseProcessSnapshot("  42 /Users/private/bin/node\n7 /usr/bin/git\n")
	if err != nil || len(processes) != 2 || processes[0] != (processFact{PID: 7, Executable: "git"}) || processes[1] != (processFact{PID: 42, Executable: "node"}) {
		t.Fatalf("processes=%+v err=%v", processes, err)
	}
	listeners, err := parseListenerSnapshot("p42\ncnode\nn*:3000\nn127.0.0.1:3000\np7\ncgit\nn[::1]:9418\n")
	if err != nil || len(listeners) != 2 || listeners[0] != (listenerFact{PID: 7, Protocol: "tcp", Port: 9418}) || listeners[1] != (listenerFact{PID: 42, Protocol: "tcp", Port: 3000}) {
		t.Fatalf("listeners=%+v err=%v", listeners, err)
	}
	serialized := strings.Join([]string{processes[0].Executable, processes[1].Executable, listeners[0].Protocol}, "\x00")
	if strings.Contains(serialized, "/Users/private") || strings.Contains(serialized, "127.0.0.1") {
		t.Fatalf("facts leaked source values: %q", serialized)
	}
}

func TestRuntimeParsersRejectHostileOrAmbiguousOutput(t *testing.T) {
	for _, output := range []string{
		"1 tool --token secret\n",
		"1 good\n1 other\n",
		"0 tool\n",
		"1 bad\x00name\n",
		"1 GITHUB_TOKEN=raw-secret\n",
		"1 ghp_123456789012345678901234567890123456\n",
	} {
		if _, err := parseProcessSnapshot(output); err != errRuntimeOutput || strings.Contains(err.Error(), output) {
			t.Fatalf("process output accepted or echoed: %q err=%v", output, err)
		}
	}
	for _, output := range []string{"n*:80\n", "p1\nnremote.example:443->other:123\n", "p1\nn*:0\n", "xprivate\n"} {
		if _, err := parseListenerSnapshot(output); err != errRuntimeOutput || strings.Contains(err.Error(), output) {
			t.Fatalf("listener output accepted or echoed: %q err=%v", output, err)
		}
	}
}
