package acceptance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/audit"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/tipublish"
)

func TestTIUpdatePublisherSeparatesMaliciousAndVulnerableSources(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	_, report, err := tipublish.Build(tipublish.Input{
		OSV:     []tipublish.Source{{Path: filepath.Join(repo, "internal/tipublish/testdata/osv-vulnerable.json"), License: "CC-BY-4.0", PublicURLBase: "https://osv.dev/vulnerability/"}},
		OpenSSF: []tipublish.Source{{Path: filepath.Join(repo, "internal/tipublish/testdata/openssf-malicious.json"), License: "CC-BY-4.0", PublicURLBase: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/"}},
		Version: "acceptance", Sequence: 1, KeyID: "ti-acceptance", GeneratedAt: now, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Malicious != 2 || report.Vulnerable != 2 {
		t.Fatalf("classifier merged sources: %+v", report)
	}
}

func TestTIUpdateSignedLifecycleAndAuditEvidence(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "ti-acceptance-2026"
	keys := bundle.KeyRegistry{bundle.FamilyTI: {keyID: public}}

	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(userHome, ".ssc-init-ti-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	layout, err := bundle.LayoutFor(home, bundle.FamilyTI)
	if err != nil {
		t.Fatal(err)
	}
	manager := &bundle.Manager{Layout: layout, Family: bundle.FamilyTI, Verifier: bundle.Verifier{Keys: keys}, Now: func() time.Time { return now }}
	feed := &mutableTIFeed{}
	server := httptest.NewTLSServer(http.HandlerFunc(feed.serveHTTP))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/s1ns3nz0/ssc-init-ti/")
	updater := bundle.Updater{Manager: manager, Client: server.Client(), Base: base, Keys: keys, Now: func() time.Time { return now }, RepositoryID: "123456789"}
	if status, _ := manager.Status(context.Background()); status.Freshness != bundle.FreshnessMissing {
		t.Fatalf("before intelligence=%s", status.Freshness)
	}

	feed.set(t, signedAcceptanceRelease(t, private, keyID, 1, now), false)
	first := updater.Update(context.Background())
	if first.Status != bundle.UpdateUpdated || first.Sequence != 1 || first.Freshness != bundle.FreshnessFresh {
		t.Fatalf("first=%+v", first)
	}

	bad := signedAcceptanceRelease(t, private, keyID, 2, now)
	feed.set(t, bad, true)
	failed := updater.Update(context.Background())
	if failed.Status != bundle.UpdateDegraded || failed.Sequence != 1 || failed.ErrorCode != bundle.UpdateErrorSignatureInvalid {
		t.Fatalf("bad signature=%+v", failed)
	}
	digestBypass := signedAcceptanceRelease(t, private, keyID, 2, now)
	digestBypass.files["ti-bundle.json"][len(digestBypass.files["ti-bundle.json"])-1] = ' '
	digestBypass.files["ti-bundle.sig"] = ed25519.Sign(private, digestBypass.files["ti-bundle.json"])
	feed.set(t, digestBypass, false)
	badDigest := updater.Update(context.Background())
	if badDigest.Status != bundle.UpdateDegraded || badDigest.Sequence != 1 || badDigest.ErrorCode != bundle.UpdateErrorBundleInvalid {
		t.Fatalf("bad digest=%+v", badDigest)
	}

	feed.set(t, signedAcceptanceRelease(t, private, keyID, 2, now), false)
	repeated := signedAcceptanceRelease(t, private, keyID, 2, now)
	for name, raw := range feed.files {
		if !bytes.Equal(raw, repeated.files[name]) {
			t.Fatalf("publisher fixture is not byte-reproducible for %s", name)
		}
	}
	second := updater.Update(context.Background())
	if second.Status != bundle.UpdateUpdated || second.Sequence != 2 || second.Malicious != 1 || second.Vulnerable != 1 {
		t.Fatalf("second=%+v", second)
	}
	feed.set(t, signedAcceptanceRelease(t, private, keyID, 1, now), false)
	requestsBeforeRollback := feed.accepts()
	rollback := updater.Update(context.Background())
	if rollback.Status != bundle.UpdateDegraded || rollback.Sequence != 2 || rollback.ErrorCode != bundle.UpdateErrorRollbackRejected {
		t.Fatalf("rollback=%+v", rollback)
	}
	if got := feed.accepts() - requestsBeforeRollback; got != 2 {
		t.Fatalf("rollback fetched %d files; bundle bytes must not be fetched", got)
	}

	active, err := manager.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "pkg:npm/evil@1.0.0", Type: model.AssetPackage, Name: "evil", Version: "1.0.0", ObservedAt: now},
		{ID: "pkg:pypi/requests@2.1.0", Type: model.AssetPackage, Name: "requests", Version: "2.1.0", ObservedAt: now},
	}}
	findings := finding.Correlate(inventory, active, now)
	if len(findings) != 2 {
		t.Fatalf("findings=%+v", findings)
	}
	var malicious, vulnerable model.Finding
	for _, item := range findings {
		if item.Verdict == model.VerdictKnownMalicious {
			malicious = item
		} else {
			vulnerable = item
		}
	}
	if malicious.Verdict != model.VerdictKnownMalicious || malicious.Level != 1 || vulnerable.Verdict != model.VerdictNeedsReview {
		t.Fatalf("malicious=%+v vulnerable=%+v", malicious, vulnerable)
	}

	run := audit.Run{ID: "run:hex:0123456789abcdef0123456789abcdef", ScanID: "scan:sha256:" + strings.Repeat("a", 64), DeviceID: "device:sha256:" + strings.Repeat("b", 64), Product: "ssc-init", Version: "dev", StartedAt: now.Add(-time.Second), FinishedAt: now}
	receipt := &audit.IntelligenceUpdate{Family: "ti", Status: string(second.Status), Freshness: string(second.Freshness), Sequence: second.Sequence, Digest: second.Digest, KeyID: second.KeyID, Records: second.Records, Malicious: second.Malicious, Vulnerable: second.Vulnerable, RecordedAt: now}
	record, err := audit.Build(model.ScanResult{Status: model.ScanComplete}, inventory, model.Delta{}, findings, run, receipt)
	if err != nil {
		t.Fatal(err)
	}
	report, err := audit.ReportText(record)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := audit.Encode(record, report)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := audit.Verify(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Record.Intelligence == nil || reloaded.Record.Intelligence.Sequence != 2 || reloaded.Record.Findings[0].Bundles[0].Sequence != 2 {
		t.Fatalf("reloaded=%+v", reloaded.Record)
	}
	for _, secret := range []string{server.URL, "PRIVATE_FIXTURE_SECRET", home} {
		if bytes.Contains(report, []byte(secret)) || bytes.Contains(archive, []byte(secret)) {
			t.Fatalf("private value persisted: %q", secret)
		}
	}
}

func TestTIUpdateDefaultRealCLIUsesZeroNetwork(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "ssc-init")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ssc-init")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	feed := &mutableTIFeed{}
	server := httptest.NewTLSServer(http.HandlerFunc(feed.serveHTTP))
	defer server.Close()
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(userHome, ".ssc-init-ti-cli-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	command := exec.Command(bin, "scan", "--baseline", "--json", "--project-root", filepath.Join(home, "project"))
	project := command.Args[len(command.Args)-1]
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	command.Env = append(os.Environ(), "HOME="+home, "SSC_INIT_TI_URL="+server.URL, "SSC_INIT_TI_KEY=PRIVATE_FIXTURE_SECRET")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("default scan: %v: %s", err, output)
	}
	if feed.accepts() != 0 {
		t.Fatalf("default scan made %d requests", feed.accepts())
	}
}

func TestTIUpdateRealCLIExplicitUpdateAffectsSameScanAndArchive(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "ti-acceptance-cli"
	feed := &mutableTIFeed{}
	server := httptest.NewTLSServer(http.HandlerFunc(feed.serveHTTP))
	defer server.Close()
	feed.set(t, signedAcceptanceRelease(t, private, keyID, 1, now), false)

	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "ssc-init")
	build := exec.Command("go", "build", "-tags", "ti_acceptance", "-o", bin, "./cmd/ssc-init")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build tagged CLI: %v: %s", err, output)
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(userHome, ".ssc-init-ti-real-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(`{"name":"fixture","lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.0.0"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "requirements.txt"), []byte("requests==2.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(home, "acceptance-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(),
		"HOME="+home, "SSL_CERT_FILE="+certificatePath,
		"SSC_INIT_ACCEPTANCE_TI_CA="+certificatePath,
		"SSC_INIT_ACCEPTANCE_TI_BASE="+server.URL+"/s1ns3nz0/ssc-init-ti/",
		"SSC_INIT_ACCEPTANCE_TI_REPOSITORY_ID=123456789", "SSC_INIT_ACCEPTANCE_TI_KEY_ID="+keyID,
		"SSC_INIT_ACCEPTANCE_TI_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(public),
	)
	run := func(args ...string) ([]byte, int) {
		t.Helper()
		command := exec.Command(bin, args...)
		command.Env = environment
		output, runErr := command.CombinedOutput()
		if runErr == nil {
			return output, 0
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return output, exitErr.ExitCode()
		}
		t.Fatalf("run %v: %v: %s", args, runErr, output)
		return nil, -1
	}
	requestsBeforeDefault := feed.accepts()
	if _, code := run("scan", "--baseline", "--json", "--project-root", project); code != 0 && code != 4 {
		t.Fatalf("default scan code=%d", code)
	}
	if got := feed.accepts(); got != requestsBeforeDefault {
		t.Fatalf("default scan made %d feed requests", got-requestsBeforeDefault)
	}
	if output, code := run("bundle", "update", "--family", "ti", "--json"); code != 0 || !bytes.Contains(output, []byte(`"sequence":1`)) {
		t.Fatalf("update code=%d output=%s", code, output)
	}
	feed.set(t, signedAcceptanceRelease(t, private, keyID, 2, now), false)
	output, code := run("scan", "--baseline", "--update-ti", "--json", "--project-root", project, "--label", "ti-real-cli")
	if code != 0 && code != 3 && code != 4 {
		t.Fatalf("scan code=%d output=%s", code, output)
	}
	for _, want := range []string{`"sequence":2`, `"status":"updated"`} {
		if !bytes.Contains(output, []byte(want)) {
			t.Fatalf("same-scan output missing %q: %s", want, output)
		}
	}

	dataDir := filepath.Join(home, "Library", "Application Support", "SSC Init")
	auditManager := &audit.Manager{Root: filepath.Join(dataDir, "audit"), Home: home, Now: time.Now, Random: rand.Reader, Render: audit.ReportText}
	listed, err := auditManager.List(context.Background())
	if err != nil || len(listed) != 2 {
		t.Fatalf("audit list=%+v err=%v", listed, err)
	}
	var updatedAudit audit.Stored
	for _, stored := range listed {
		if stored.Label == "ti-real-cli" {
			updatedAudit = stored
		}
	}
	if updatedAudit.RunID == "" {
		t.Fatalf("updated audit missing: %+v", listed)
	}
	verified, err := auditManager.Open(context.Background(), updatedAudit.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Record.Intelligence == nil || verified.Record.Intelligence.Sequence != 2 {
		t.Fatalf("archive intelligence=%+v", verified.Record.Intelligence)
	}
	var gotMalicious, gotVulnerable bool
	for _, item := range verified.Record.Findings {
		gotMalicious = gotMalicious || item.Verdict == model.VerdictKnownMalicious
		gotVulnerable = gotVulnerable || item.Verdict == model.VerdictNeedsReview
		if len(item.Bundles) != 1 || item.Bundles[0].Sequence != 2 {
			t.Fatalf("finding evaluated against pre-update bundle: %+v", item)
		}
	}
	if !gotMalicious || !gotVulnerable {
		t.Fatalf("archived findings=%+v", verified.Record.Findings)
	}
	archivePath := filepath.Join(dataDir, "audit", filepath.Base(updatedAudit.SafePath))
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{server.URL, certificatePath, home, "SSC_INIT_ACCEPTANCE_TI_PUBLIC_KEY"} {
		if bytes.Contains(output, []byte(privateValue)) || bytes.Contains(raw, []byte(privateValue)) {
			t.Fatalf("private value escaped: %q", privateValue)
		}
	}
}

type acceptanceRelease struct{ files map[string][]byte }
type mutableTIFeed struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests int
}

func (f *mutableTIFeed) set(t *testing.T, release acceptanceRelease, corruptManifestSignature bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = release.files
	if corruptManifestSignature {
		f.files["ti-manifest.sig"] = append([]byte(nil), f.files["ti-manifest.sig"]...)
		f.files["ti-manifest.sig"][0] ^= 1
	}
}
func (f *mutableTIFeed) accepts() int { f.mu.Lock(); defer f.mu.Unlock(); return f.requests }
func (f *mutableTIFeed) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	name := filepath.Base(r.URL.Path)
	raw, ok := f.files[name]
	if !ok || r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(raw)
}

func signedAcceptanceRelease(t *testing.T, private ed25519.PrivateKey, keyID string, sequence uint64, now time.Time) acceptanceRelease {
	t.Helper()
	records := []bundle.TIRecord{
		{ID: "MAL-2026-0001", AssetID: "pkg:npm/evil", VersionRange: "osv:exact:1.0.0", Verdict: "known-malicious", Confidence: "high", SourceURLs: []string{"https://github.com/ossf/malicious-packages/commit/example"}, RetrievedAt: now.Format(time.RFC3339), ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339), License: "CC-BY-4.0", Redistributable: true},
		{ID: "OSV-2026-0001", AssetID: "pkg:pypi/requests", VersionRange: "osv:ecosystem:>=2.0.0 <2.5.0", Verdict: "needs-review", Confidence: "medium", SourceURLs: []string{"https://osv.dev/vulnerability/OSV-2026-0001"}, RetrievedAt: now.Format(time.RFC3339), ValidUntil: now.Add(24 * time.Hour).Format(time.RFC3339), License: "CC-BY-4.0", Redistributable: true},
	}
	payload, _ := json.Marshal(bundle.TIPayload{Records: records})
	envelope := bundle.Envelope{SchemaVersion: bundle.SchemaVersion, Family: bundle.FamilyTI, Version: fmt.Sprintf("acceptance-%d", sequence), Sequence: sequence, KeyID: keyID, GeneratedAt: now, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour), Payload: payload}
	bundleRaw, _ := json.Marshal(envelope)
	bundleRaw = append(bundleRaw, '\n')
	digest := sha256.Sum256(bundleRaw)
	manifest := bundle.Manifest{SchemaVersion: bundle.ManifestSchemaVersion, Family: bundle.FamilyTI, Version: envelope.Version, Sequence: sequence, KeyID: keyID, GeneratedAt: envelope.GeneratedAt, ValidFrom: envelope.ValidFrom, ValidUntil: envelope.ValidUntil, Length: int64(len(bundleRaw)), SHA256: hex.EncodeToString(digest[:]), ReleaseTag: fmt.Sprintf("ti-%08d", sequence), Artifact: "ti-bundle.json"}
	manifestRaw, _ := json.Marshal(manifest)
	manifestRaw = append(manifestRaw, '\n')
	return acceptanceRelease{files: map[string][]byte{"ti-manifest.json": manifestRaw, "ti-manifest.sig": ed25519.Sign(private, manifestRaw), "ti-bundle.json": bundleRaw, "ti-bundle.sig": ed25519.Sign(private, bundleRaw)}}
}
