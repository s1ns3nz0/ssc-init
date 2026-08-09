package adapter

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

const (
	SchemaV1         = "ssc-init.adapter-invocation.v1"
	ManifestSchemaV1 = "ssc-init.adapter-capabilities.v1"
)

type Host string

const (
	HostClaude Host = "claude"
	HostCodex  Host = "codex"
	HostCursor Host = "cursor"
)

type Event string

const (
	EventOnDemand      Event = "on-demand"
	EventPostExecution Event = "post-execution"
	EventPreExecution  Event = "pre-execution"
	EventScheduled     Event = "scheduled"
)

type Capability string

const (
	CapabilityAdvisory     Capability = "advisory"
	CapabilityOnDemand     Capability = "on-demand"
	CapabilityPreExecution Capability = "pre-execution"
	CapabilityScheduled    Capability = "scheduled"
)

type Invocation struct {
	SchemaVersion string     `json:"schemaVersion"`
	Host          Host       `json:"host"`
	Event         Event      `json:"event"`
	Capability    Capability `json:"capability"`
	AssetIDs      []string   `json:"assetIds,omitempty"`
}

func (v Invocation) Valid() bool {
	if v.SchemaVersion != SchemaV1 || !validHost(v.Host) || !validEventCapability(v.Event, v.Capability) || len(v.AssetIDs) > 256 {
		return false
	}
	for index, id := range v.AssetIDs {
		if !validCanonicalID(id) || index > 0 && v.AssetIDs[index-1] >= id {
			return false
		}
	}
	return sort.StringsAreSorted(v.AssetIDs)
}

type EventCapability struct {
	Event      Event      `json:"event"`
	Capability Capability `json:"capability"`
}

type CapabilityManifest struct {
	SchemaVersion string            `json:"schemaVersion"`
	Host          Host              `json:"host"`
	Events        []EventCapability `json:"events"`
}

func (m CapabilityManifest) Valid() bool {
	if m.SchemaVersion != ManifestSchemaV1 || !validHost(m.Host) || len(m.Events) == 0 || len(m.Events) > 4 {
		return false
	}
	for index, item := range m.Events {
		if !validEventCapability(item.Event, item.Capability) || index > 0 && m.Events[index-1].Event >= item.Event {
			return false
		}
	}
	return true
}

func validHost(value Host) bool {
	switch value {
	case HostClaude, HostCodex, HostCursor:
		return true
	default:
		return false
	}
}

func validEventCapability(event Event, capability Capability) bool {
	if capability == CapabilityAdvisory {
		return event == EventOnDemand || event == EventPostExecution || event == EventPreExecution || event == EventScheduled
	}
	switch event {
	case EventOnDemand:
		return capability == CapabilityOnDemand
	case EventPreExecution:
		return capability == CapabilityPreExecution
	case EventScheduled:
		return capability == CapabilityScheduled
	default:
		return false
	}
}

func validCanonicalID(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || privacy.ContainsSensitiveValue(value) {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) || unicode.IsSpace(current) {
			return false
		}
	}
	return true
}
