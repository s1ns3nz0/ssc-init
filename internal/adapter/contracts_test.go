package adapter

import (
	"strings"
	"testing"
)

func TestInvocationAcceptsOnlyClosedBoundedValues(t *testing.T) {
	valid := Invocation{
		SchemaVersion: SchemaV1, Host: HostClaude, Event: EventOnDemand,
		Capability: CapabilityOnDemand, AssetIDs: []string{"agent-plugin:claude:demo@1.0.0"},
	}
	if !valid.Valid() {
		t.Fatal("valid invocation rejected")
	}
	for name, mutate := range map[string]func(*Invocation){
		"schema":     func(v *Invocation) { v.SchemaVersion = "ssc-init.adapter.v2" },
		"host":       func(v *Invocation) { v.Host = "other" },
		"event":      func(v *Invocation) { v.Event = "other" },
		"capability": func(v *Invocation) { v.Capability = "enforced" },
		"mismatch":   func(v *Invocation) { v.Capability = CapabilityScheduled },
		"duplicate":  func(v *Invocation) { v.AssetIDs = append(v.AssetIDs, v.AssetIDs[0]) },
		"unsorted":   func(v *Invocation) { v.AssetIDs = []string{"tool:z", "tool:a"} },
		"oversize":   func(v *Invocation) { v.AssetIDs = []string{strings.Repeat("a", 513)} },
		"path":       func(v *Invocation) { v.AssetIDs = []string{"/Users/private/plugin"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.AssetIDs = append([]string(nil), valid.AssetIDs...)
			mutate(&candidate)
			if candidate.Valid() {
				t.Fatalf("invalid invocation accepted: %+v", candidate)
			}
		})
	}
}

func TestCapabilityManifestRejectsContradictionsAndDuplicates(t *testing.T) {
	valid := CapabilityManifest{SchemaVersion: ManifestSchemaV1, Host: HostCursor, Events: []EventCapability{
		{Event: EventOnDemand, Capability: CapabilityOnDemand},
		{Event: EventPostExecution, Capability: CapabilityAdvisory},
		{Event: EventPreExecution, Capability: CapabilityPreExecution},
		{Event: EventScheduled, Capability: CapabilityScheduled},
	}}
	if !valid.Valid() {
		t.Fatal("valid manifest rejected")
	}
	for _, candidate := range []CapabilityManifest{
		{SchemaVersion: ManifestSchemaV1, Host: HostCursor},
		{SchemaVersion: ManifestSchemaV1, Host: HostCursor, Events: []EventCapability{{Event: EventPreExecution, Capability: CapabilityScheduled}}},
		{SchemaVersion: ManifestSchemaV1, Host: HostCursor, Events: []EventCapability{{Event: EventOnDemand, Capability: CapabilityOnDemand}, {Event: EventOnDemand, Capability: CapabilityAdvisory}}},
		{SchemaVersion: ManifestSchemaV1, Host: HostCursor, Events: []EventCapability{{Event: EventScheduled, Capability: CapabilityScheduled}, {Event: EventOnDemand, Capability: CapabilityOnDemand}}},
	} {
		if candidate.Valid() {
			t.Fatalf("invalid manifest accepted: %+v", candidate)
		}
	}
}

func TestEverySupportedHostUsesTheSameClosedContract(t *testing.T) {
	for _, host := range []Host{HostClaude, HostCodex, HostCursor} {
		if !(Invocation{SchemaVersion: SchemaV1, Host: host, Event: EventPostExecution, Capability: CapabilityAdvisory}).Valid() {
			t.Fatalf("host %q rejected", host)
		}
	}
}
