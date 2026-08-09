package policy

import (
	_ "embed"
	"slices"
)

//go:embed starter.json
var starterDocument []byte

// Starter returns an independent copy of the shipped inert level-5 policy.
func Starter() []byte { return slices.Clone(starterDocument) }
