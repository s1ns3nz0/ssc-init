package mcp

import "testing"

func TestValidServerSemanticListsRequiresSortedUniqueItems(t *testing.T) {
	if !validServerSemanticLists(ServerConfig{
		EnvKeys: []string{"A", "B"}, HeaderKeys: []string{"A", "B"},
		EnabledTools: []string{"A", "B"}, DisabledTools: []string{"A", "B"},
	}) {
		t.Fatal("sorted unique semantic lists rejected")
	}
	for _, test := range []struct {
		name   string
		server ServerConfig
	}{
		{"env unsorted", ServerConfig{EnvKeys: []string{"B", "A"}}},
		{"env duplicate", ServerConfig{EnvKeys: []string{"A", "A"}}},
		{"header unsorted", ServerConfig{HeaderKeys: []string{"B", "A"}}},
		{"header duplicate", ServerConfig{HeaderKeys: []string{"A", "A"}}},
		{"enabled tool unsorted", ServerConfig{EnabledTools: []string{"B", "A"}}},
		{"enabled tool duplicate", ServerConfig{EnabledTools: []string{"A", "A"}}},
		{"disabled tool unsorted", ServerConfig{DisabledTools: []string{"B", "A"}}},
		{"disabled tool duplicate", ServerConfig{DisabledTools: []string{"A", "A"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if validServerSemanticLists(test.server) {
				t.Fatal("noncanonical semantic list accepted")
			}
		})
	}
}
