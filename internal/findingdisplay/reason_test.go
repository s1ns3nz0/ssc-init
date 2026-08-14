package findingdisplay

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestReasonExplainsVerifiedMaliciousPackageMatch(t *testing.T) {
	finding := model.Finding{Verdict: model.VerdictKnownMalicious, IntelligenceIDs: []string{"MAL-2026-0042"}}
	if got := Reason(finding); got != "verified malicious-package intelligence matched this exact package version" {
		t.Fatalf("reason=%q", got)
	}
}

func TestReasonExplainsOSVAffectedVersionWithPublicAdvisory(t *testing.T) {
	finding := model.Finding{Verdict: model.VerdictNeedsReview, IntelligenceIDs: []string{"GHSA-abcd-1234-wxyz"}}
	if got := Reason(finding); got != "this installed version is affected by GHSA-abcd-1234-wxyz" {
		t.Fatalf("reason=%q", got)
	}
}

func TestReasonDoesNotCallOpaqueKnownMaliciousIDPackageIntelligence(t *testing.T) {
	finding := model.Finding{Verdict: model.VerdictKnownMalicious, IntelligenceIDs: []string{"ti:opaque"}}
	if got := Reason(finding); got != "verified threat intelligence matched this asset" {
		t.Fatalf("reason=%q", got)
	}
}

func TestPublicAdvisoriesExcludeTransportAndOpaqueIdentifiers(t *testing.T) {
	finding := model.Finding{IntelligenceIDs: []string{
		"GHSA-abcd-1234-wxyz", "https://osv.dev/vulnerability/GHSA-secret?q=private", "/Users/alice/private", "secret.example",
		"PRIVATE_RESPONSE_BODY", "PRIVATE_SIGNING_KEY", "raw source text", "evidence:sha256:" + strings.Repeat("c", 64),
	}}
	if got := PublicAdvisories(finding); got != "GHSA-abcd-1234-wxyz" {
		t.Fatalf("advisories=%q", got)
	}
}
