package collector

import (
	"sync/atomic"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
)

type trackingRuntimeClearer struct{ calls atomic.Int32 }

func (value *trackingRuntimeClearer) ClearRuntimeEvidence() { value.calls.Add(1) }

func TestClearLocalEvidenceTargetsInvokesEveryFullCapacityRuntimeHook(t *testing.T) {
	logical := &trackingRuntimeClearer{}
	spareOne := &trackingRuntimeClearer{}
	spareTwo := &trackingRuntimeClearer{}
	issuer := &trackingRuntimeClearer{}
	backing := make([]model.LocalEvidenceTarget, 1, 4)
	full := backing[:cap(backing)]
	full[0].Provenance = logical
	full[1].Provenance = logical
	full[2].Provenance = spareOne
	full[3].Provenance = spareTwo
	results := []model.CollectorResult{{LocalEvidenceIssuer: issuer, LocalEvidenceTargets: backing}}

	ClearLocalEvidenceTargets(results)

	for name, value := range map[string]*trackingRuntimeClearer{"logical": logical, "spare-one": spareOne, "spare-two": spareTwo, "issuer": issuer} {
		if value.calls.Load() != 1 {
			t.Fatalf("%s calls=%d", name, value.calls.Load())
		}
	}
	if results[0].LocalEvidenceIssuer != nil || results[0].LocalEvidenceTargets != nil {
		t.Fatalf("runtime fields survived: %+v", results[0])
	}
	for index := range full {
		if full[index] != (model.LocalEvidenceTarget{}) {
			t.Fatalf("full[%d]=%+v", index, full[index])
		}
	}
}
