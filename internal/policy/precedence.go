package policy

// Level is one policy precedence level. Every level is present in every build;
// an unavailable source makes its level explicitly inactive rather than
// silently removing it from the decision order.
type Level struct {
	Number int    `json:"level"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
}

// MaliciousIndex is the level-1 seam for threat intelligence. Production has
// no implementation yet, so a nil index is the normal honest state.
type MaliciousIndex interface {
	KnownMalicious(assetID, digest string) bool
}

// Sources are the independently loaded inputs to precedence evaluation. A
// local Document supplies only levels 4 and 5; it cannot construct a Bundle.
type Sources struct {
	Intelligence MaliciousIndex
	Bundle       *Bundle
	Document     Document
}

// Bundle represents verified organization policy. No loader constructs one in
// the local-policy build; its activation pipeline belongs to [BUNDLE].
type Bundle struct{ _ struct{} }

// Levels returns the closed, ordered policy precedence ladder.
func Levels(sources Sources) []Level {
	intelligence := Level{Number: 1, Name: "known-malicious-evidence", Active: sources.Intelligence != nil}
	if !intelligence.Active {
		intelligence.Reason = "no evidence available"
	}
	deny := Level{Number: 2, Name: "organization-deny", Active: sources.Bundle != nil}
	allow := Level{Number: 3, Name: "organization-allow", Active: sources.Bundle != nil}
	if sources.Bundle == nil {
		deny.Reason = "no bundle present"
		allow.Reason = "no bundle present"
	}
	return []Level{
		intelligence,
		deny,
		allow,
		{Number: 4, Name: "user-exceptions", Active: true},
		{Number: 5, Name: "default-product-policy", Active: true},
	}
}

// KnownMalicious asks level 1 to decide. The reason is populated only when the
// level is inert; an active index returning false is a real negative decision.
func KnownMalicious(sources Sources, assetID, digest string) (bool, string) {
	if sources.Intelligence == nil {
		return false, "no evidence available"
	}
	return sources.Intelligence.KnownMalicious(assetID, digest), ""
}
