package identity

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
)

func TestFinalizeObservationCanonicalizesConsumersAndID(t *testing.T) {
	input := model.Observation{
		AssetID: "mcp:shared:workspace", Collector: "mcp",
		Consumers: []string{"vscode", "claude", "vscode"},
		Scope:     model.ScopeProject, LocationRef: "$HOME/Projects/a/.mcp.json",
		ProjectID: "project:sha256:abc", Source: "mcp",
	}
	got, err := FinalizeObservation(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Consumers, []string{"claude", "vscode"}) {
		t.Fatalf("consumers=%q", got.Consumers)
	}
	if got.ID != "observation:sha256:02b164e37c428313b30c9f1231f3ba9fc44c01dbbef8f6ae4d1cb8ca25d459c2" {
		t.Fatalf("id=%q", got.ID)
	}
}

func TestFinalizeObservationRejectsSensitiveIdentityWithoutEcho(t *testing.T) {
	candidate := model.Observation{AssetID: "agent:ghp_123456789012345678901234567890123456", Collector: "agents", Scope: model.ScopeUser, LocationRef: "$HOME/.claude/plugins/rejected"}
	_, err := FinalizeObservation(candidate)
	if !errors.Is(err, ErrRejectedIdentity) || strings.Contains(err.Error(), "ghp_") {
		t.Fatalf("err=%v", err)
	}
}

func TestSafeLocationRefHidesOutsideHome(t *testing.T) {
	got := SafeLocationRef("/Users/test", "/Volumes/work/client/project", "external-root-1")
	if !strings.HasPrefix(got, "external-root-1/path-sha256:") || strings.Contains(got, "/Volumes/") {
		t.Fatalf("ref=%q", got)
	}
}

func TestSafeLocationRefRedactsHomeBoundary(t *testing.T) {
	if got := SafeLocationRef("/Users/test", "/Users/test/Projects/a/.mcp.json", "external-root-1"); got != "$HOME/Projects/a/.mcp.json" {
		t.Fatalf("ref=%q", got)
	}
}
