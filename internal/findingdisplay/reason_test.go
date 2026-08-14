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
	finding := model.Finding{Verdict: model.VerdictNeedsReview, IntelligenceIDs: []string{"GHSA-2345-6789-cfgh"}}
	if got := Reason(finding); got != "this installed version is affected by GHSA-2345-6789-cfgh" {
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
		"GHSA-2345-6789-cfgh", "https://osv.dev/vulnerability/GHSA-secret?q=private", "/Users/alice/private", "secret.example",
		"PRIVATE_RESPONSE_BODY", "PRIVATE_SIGNING_KEY", "raw source text", "evidence:sha256:" + strings.Repeat("c", 64),
	}}
	if got := PublicAdvisories(finding); got != "GHSA-2345-6789-cfgh" {
		t.Fatalf("advisories=%q", got)
	}
}

func TestPublicAdvisoriesUsesClosedProducerBackedNamespaces(t *testing.T) {
	finding := model.Finding{IntelligenceIDs: []string{
		"CVE-2026-12345", "GHSA-2345-6789-cfgh", "GO-2026-1", "MAL-2026-0042#001", "OSV-2026-77",
		"CUSTOMER-TICKET-42", "GHSA-abcd-1234-wxyz", "INTERNAL-CASE-1234", "MAL-SINGLE", "SOURCE-RESPONSE-2026",
	}}
	want := "CVE-2026-12345, GHSA-2345-6789-cfgh, GO-2026-1, MAL-2026-0042, OSV-2026-77"
	if got := PublicAdvisories(finding); got != want {
		t.Fatalf("advisories=%q want=%q", got, want)
	}
}

func TestReasonDoesNotDescribeOpaqueHyphenIDAsAffectedVersion(t *testing.T) {
	finding := model.Finding{Verdict: model.VerdictNeedsReview, IntelligenceIDs: []string{"INTERNAL-CASE-1234"}}
	if got := Reason(finding); got != "verified threat intelligence matched this asset" {
		t.Fatalf("reason=%q", got)
	}
}
