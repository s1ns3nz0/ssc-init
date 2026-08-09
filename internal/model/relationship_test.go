package model

import "testing"

func TestRelationshipKindsAreClosed(t *testing.T) {
	for _, kind := range []string{
		RelationshipContains,
		RelationshipConfigures,
		RelationshipUses,
		RelationshipSameAs,
		RelationshipProbedBy,
		RelationshipDeclaredBy,
		RelationshipResolvesTo,
		RelationshipExecutes,
		RelationshipConnectsTo,
	} {
		if !ValidRelationshipKind(kind) {
			t.Fatalf("kind %q is not valid", kind)
		}
	}
	for _, kind := range []string{"", "unknown", "PROBED-BY", " probed-by"} {
		if ValidRelationshipKind(kind) {
			t.Fatalf("kind %q unexpectedly valid", kind)
		}
	}
}
