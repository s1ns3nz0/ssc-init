package collector

import (
	"sync/atomic"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type trackingRuntimeClearer struct{ calls atomic.Int32 }

func (value *trackingRuntimeClearer) ClearRuntimeEvidence() { value.calls.Add(1) }

type sliceRuntimeClearer []*trackingRuntimeClearer

func (values sliceRuntimeClearer) ClearRuntimeEvidence() {
	for _, value := range values {
		value.ClearRuntimeEvidence()
	}
}

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

	for name, want := range map[string]struct {
		value *trackingRuntimeClearer
		calls int32
	}{
		"logical":   {value: logical, calls: 2},
		"spare-one": {value: spareOne, calls: 1},
		"spare-two": {value: spareTwo, calls: 1},
		"issuer":    {value: issuer, calls: 1},
	} {
		if want.value.calls.Load() != want.calls {
			t.Fatalf("%s calls=%d want=%d", name, want.value.calls.Load(), want.calls)
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

func TestClearLocalEvidenceTargetsAcceptsNonComparableRuntimeHook(t *testing.T) {
	tracked := &trackingRuntimeClearer{}
	hook := sliceRuntimeClearer{tracked}
	backing := make([]model.LocalEvidenceTarget, 1, 2)
	full := backing[:cap(backing)]
	full[1].Provenance = hook
	results := []model.CollectorResult{{LocalEvidenceTargets: backing}}

	ClearLocalEvidenceTargets(results)

	if tracked.calls.Load() != 1 {
		t.Fatalf("slice hook calls=%d", tracked.calls.Load())
	}
	if results[0].LocalEvidenceTargets != nil || full[1] != (model.LocalEvidenceTarget{}) {
		t.Fatalf("runtime state survived: result=%+v spare=%+v", results[0], full[1])
	}
}
