package bundle

import (
	"strings"
	"testing"
	"time"
)

func TestLoadAcceptsClosedThreatIntelligenceEnvelope(t *testing.T) {
	raw := []byte(`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","version":"2026.08.10","sequence":7,"keyId":"ti-2026","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"records":[]}}`)
	got, err := Load(raw, time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC))
	if err != nil || got.Family != FamilyTI || got.Sequence != 7 || got.TI == nil || got.Policy != nil {
		t.Fatalf("bundle=%+v err=%v", got, err)
	}
}

func TestLoadAcceptsClosedOrganizationPolicyEnvelope(t *testing.T) {
	raw := []byte(`{"schemaVersion":"ssc-init.bundle.v1","family":"policy","version":"2026.08.10","sequence":8,"keyId":"policy-2026","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"denies":[],"allows":[],"exceptions":[],"tests":[]}}`)
	got, err := Load(raw, time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC))
	if err != nil || got.Family != FamilyPolicy || got.Policy == nil || got.TI != nil {
		t.Fatalf("bundle=%+v err=%v", got, err)
	}
}

func TestLoadRejectsUnknownDuplicateInvalidAndExpiredWithoutEcho(t *testing.T) {
	secret := "GITHUB_TOKEN=raw-secret"
	cases := []string{
		`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","family":"policy","version":"v","sequence":1,"keyId":"k","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"records":[]}}`,
		`{"schemaVersion":"ssc-init.bundle.v1","family":"other","version":"v","sequence":1,"keyId":"k","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{}}`,
		`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","version":"v","sequence":0,"keyId":"k","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"records":[]}}`,
		`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","version":"v","sequence":1,"keyId":"k","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-11T00:00:00Z","payload":{"records":[]}}`,
		`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","version":"v","sequence":1,"keyId":"k","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"records":[]},"` + secret + `":true}`,
	}
	for _, raw := range cases {
		if _, err := Load([]byte(raw), time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("accepted or echoed hostile bundle: err=%v", err)
		}
	}
}
