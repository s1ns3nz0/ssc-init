package platform

import "testing"

func TestRedactHomeOnlyOnPathBoundary(t *testing.T) {
	home := "/Users/alice"

	if got := RedactHome(home, "/Users/alice/.claude/settings.json"); got != "$HOME/.claude/settings.json" {
		t.Fatal(got)
	}
	if got := RedactHome(home, "/Users/alice2/file"); got != "/Users/alice2/file" {
		t.Fatal(got)
	}
}
