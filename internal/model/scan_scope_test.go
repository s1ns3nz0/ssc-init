package model

import "testing"

func TestScanScopeModeIsClosed(t *testing.T) {
	if !ScanScopeHost.Valid() || !ScanScopeProjectOnly.Valid() {
		t.Fatal("documented scan scope modes are invalid")
	}
	for _, value := range []ScanScopeMode{"", "project", "all"} {
		if value.Valid() {
			t.Fatalf("accepted mode %q", value)
		}
	}
}
