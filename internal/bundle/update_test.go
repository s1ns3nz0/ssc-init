package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type updateFeed struct {
	server      *httptest.Server
	base        *url.URL
	requests    atomic.Int64
	manifest    []byte
	manifestSig []byte
	bundle      []byte
	bundleSig   []byte
	privateKey  ed25519.PrivateKey
}

func newUpdateFeed(t *testing.T) (*updateFeed, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey := deterministicKey(t, "update feed")
	f := &updateFeed{privateKey: privateKey}
	f.setBundle(t, validTIBundleBytes("ti-key"))
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			http.Error(w, "secret body", http.StatusBadRequest)
			return
		}
		var manifest Manifest
		_ = json.Unmarshal(f.manifest, &manifest)
		switch r.URL.Path {
		case "/s1ns3nz0/ssc-init-ti/releases/latest/download/ti-manifest.json":
			w.Write(f.manifest)
		case "/s1ns3nz0/ssc-init-ti/releases/latest/download/ti-manifest.sig":
			w.Write(f.manifestSig)
		case "/s1ns3nz0/ssc-init-ti/releases/download/" + manifest.ReleaseTag + "/ti-bundle.json":
			f.requests.Add(1)
			w.Write(f.bundle)
		case "/s1ns3nz0/ssc-init-ti/releases/download/" + manifest.ReleaseTag + "/ti-bundle.sig":
			w.Write(f.bundleSig)
		default:
			http.Error(w, "remote-secret", http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)
	f.base, _ = url.Parse(f.server.URL + "/s1ns3nz0/ssc-init-ti/")
	return f, publicKey
}

func (f *updateFeed) setBundle(t *testing.T, raw []byte) {
	t.Helper()
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Family: FamilyTI, Version: envelope.Version, Sequence: envelope.Sequence, KeyID: envelope.KeyID, GeneratedAt: envelope.GeneratedAt, ValidFrom: envelope.ValidFrom, ValidUntil: envelope.ValidUntil, Length: int64(len(raw)), SHA256: hex.EncodeToString(sum[:]), ReleaseTag: "ti-" + leftPadSequence(envelope.Sequence), Artifact: "ti-bundle.json"}
	f.manifest, _ = json.Marshal(manifest)
	f.manifest = append(f.manifest, '\n')
	f.manifestSig = ed25519.Sign(f.privateKey, f.manifest)
	f.bundle = raw
	f.bundleSig = ed25519.Sign(f.privateKey, raw)
}

func leftPadSequence(sequence uint64) string { return fmt.Sprintf("%08d", sequence) }

func updaterForFeed(t *testing.T, f *updateFeed, publicKey ed25519.PublicKey) Updater {
	t.Helper()
	m := testManager(t, t.TempDir(), publicKey)
	return Updater{Manager: &m, Client: f.server.Client(), Base: f.base, Keys: KeyRegistry{FamilyTI: {"ti-key": publicKey}}, Now: testBundleNow, RepositoryID: "123456789"}
}

func TestUpdaterMovesMissingToFreshAndNoOpsWhenCurrent(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	first := u.Update(context.Background())
	second := u.Update(context.Background())
	if first.Status != UpdateUpdated || first.Sequence != 7 || first.Freshness != FreshnessFresh {
		t.Fatalf("first=%+v", first)
	}
	if second.Status != UpdateCurrent || f.requests.Load() != 1 {
		t.Fatalf("second=%+v requests=%d", second, f.requests.Load())
	}
}

func TestUpdaterRejectsRollbackEquivocationAndRetainsLastKnownGood(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	good := u.Update(context.Background())
	if good.Status != UpdateUpdated {
		t.Fatalf("good=%+v", good)
	}
	var manifest Manifest
	if err := json.Unmarshal(f.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	f.manifest, _ = json.Marshal(manifest)
	f.manifest = append(f.manifest, '\n')
	// Signature deliberately remains for the old exact bytes.
	failed := u.Update(context.Background())
	if failed.Status != UpdateDegraded || failed.ErrorCode != UpdateErrorSignatureInvalid || failed.Sequence != 7 {
		t.Fatalf("failed=%+v", failed)
	}
	status, _ := u.Manager.Status(context.Background())
	if status.Sequence != 7 || status.Freshness != FreshnessFresh {
		t.Fatalf("lkg=%+v", status)
	}
}

func TestUpdaterActivatesNewerAndRejectsLowerAndEquivocation(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	if got := u.Update(context.Background()); got.Status != UpdateUpdated {
		t.Fatalf("initial=%+v", got)
	}
	f.setBundle(t, validTIBundleSequenceBytes("ti-key", 8))
	if got := u.Update(context.Background()); got.Status != UpdateUpdated || got.Sequence != 8 {
		t.Fatalf("newer=%+v", got)
	}
	f.setBundle(t, validTIBundleSequenceBytes("ti-key", 7))
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorRollbackRejected || got.Sequence != 8 {
		t.Fatalf("lower=%+v", got)
	}
	raw := append(validTIBundleSequenceBytes("ti-key", 8), '\n')
	f.setBundle(t, raw)
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorRollbackRejected || got.Sequence != 8 {
		t.Fatalf("equivocation=%+v", got)
	}
}

func TestUpdaterRejectsTamperedBundleAndDeclaredLengthBeforeActivation(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	f.bundle[0] ^= 1
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorBundleInvalid || got.Status != UpdateUnavailable {
		t.Fatalf("tamper=%+v", got)
	}
	f.setBundle(t, validTIBundleBytes("ti-key"))
	var manifest Manifest
	_ = json.Unmarshal(f.manifest, &manifest)
	manifest.Length--
	f.manifest, _ = json.Marshal(manifest)
	f.manifest = append(f.manifest, '\n')
	f.manifestSig = ed25519.Sign(f.privateKey, f.manifest)
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorResponseLimit {
		t.Fatalf("length=%+v", got)
	}
}

func TestUpdaterChecksDigestBeforeActivation(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	// Keep a valid bundle signature but make the bytes disagree with the signed manifest.
	f.bundle = append(f.bundle, '\n')
	f.bundleSig = ed25519.Sign(f.privateKey, f.bundle)
	var manifest Manifest
	_ = json.Unmarshal(f.manifest, &manifest)
	manifest.Length = int64(len(f.bundle))
	f.manifest, _ = json.Marshal(manifest)
	f.manifest = append(f.manifest, '\n')
	f.manifestSig = ed25519.Sign(f.privateKey, f.manifest)
	result := u.Update(context.Background())
	if result.ErrorCode != UpdateErrorBundleInvalid || result.Status != UpdateUnavailable {
		t.Fatalf("result=%+v", result)
	}
	status, _ := u.Manager.Status(context.Background())
	if status.Freshness != FreshnessMissing {
		t.Fatalf("bytes activated before digest check: %+v", status)
	}
}

func TestUpdaterRejectsOversizeManifestAndCancellationWithClosedResults(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	f.manifest = make([]byte, maxManifestBytes+1)
	result := u.Update(context.Background())
	if result.ErrorCode != UpdateErrorResponseLimit || result.Status != UpdateUnavailable {
		t.Fatalf("limit=%+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = u.Update(ctx)
	if result.ErrorCode != UpdateErrorCancellation || result.Status != UpdateUnavailable {
		t.Fatalf("cancel=%+v", result)
	}
}

func TestUpdaterRejectsCrossHostRedirectWithoutFollowing(t *testing.T) {
	f, key := newUpdateFeed(t)
	evilHit := atomic.Bool{}
	evil := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilHit.Store(true) }))
	defer evil.Close()
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL+"/steal", http.StatusFound) })
	u := updaterForFeed(t, f, key)
	result := u.Update(context.Background())
	if result.ErrorCode != UpdateErrorRedirectRejected || evilHit.Load() {
		t.Fatalf("result=%+v evil=%v", result, evilHit.Load())
	}
}

func TestUpdaterRejectsAllowlistedAssetHostInvalidAuthorityAndPath(t *testing.T) {
	for _, location := range []string{
		"https://release-assets.githubusercontent.com:8443/github-production-release-asset/1/x/ti-manifest.json",
		"https://release-assets.githubusercontent.com/arbitrary/ti-manifest.json",
		"https://objects.githubusercontent.com/arbitrary/ti-manifest.json",
		"https://github-releases.githubusercontent.com/not-a-repository/ti-manifest.json",
	} {
		t.Run(location, func(t *testing.T) {
			f, key := newUpdateFeed(t)
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, location, http.StatusFound) })
			result := updaterForFeed(t, f, key).Update(context.Background())
			if result.ErrorCode != UpdateErrorRedirectRejected {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestUpdaterBindsReleaseAssetRedirectsToExactRepositoryID(t *testing.T) {
	base, _ := url.Parse("https://github.com/s1ns3nz0/ssc-init-ti/")
	source := "/s1ns3nz0/ssc-init-ti/releases/download/ti-00000007/ti-bundle.json"
	for _, raw := range []string{
		"https://release-assets.githubusercontent.com/github-production-release-asset/123456789/uuid/ti-bundle.json",
		"https://objects.githubusercontent.com/github-production-release-asset-2e65be/123456789/uuid/ti-bundle.json",
		"https://github-releases.githubusercontent.com/123456789/uuid/ti-bundle.json",
	} {
		target, _ := url.Parse(raw)
		if !validFetchURL(target, base, "ti-bundle.json", source, "123456789") {
			t.Fatalf("exact feed ID rejected: %s", raw)
		}
	}
	for _, raw := range []string{
		"https://release-assets.githubusercontent.com/github-production-release-asset/987654321/uuid/ti-bundle.json",
		"https://objects.githubusercontent.com/github-production-release-asset-2e65be/987654321/uuid/ti-bundle.json",
		"https://github-releases.githubusercontent.com/987654321/uuid/ti-bundle.json",
	} {
		target, _ := url.Parse(raw)
		if validFetchURL(target, base, "ti-bundle.json", source, "123456789") {
			t.Fatalf("different repository ID accepted: %s", raw)
		}
	}
}

func TestUpdaterAcceptsOnlyCDNSignedQueryAfterRepositoryBoundRedirect(t *testing.T) {
	base, _ := url.Parse("https://github.com/s1ns3nz0/ssc-init-ti/")
	source := "/s1ns3nz0/ssc-init-ti/releases/download/ti-00000007/ti-bundle.json"
	cdn, _ := url.Parse("https://release-assets.githubusercontent.com/github-production-release-asset/123456789/asset-uuid?sp=r&sig=opaque&jwt=opaque&response-content-disposition=attachment%3B%20filename%3Dti-bundle.json")
	if !validFetchURL(cdn, base, "ti-bundle.json", source, "123456789") {
		t.Fatal("repository-bound GitHub CDN signed query rejected")
	}
	for _, raw := range []string{
		"https://github.com/s1ns3nz0/ssc-init-ti/releases/download/ti-00000007/ti-bundle.json?sig=opaque",
		"https://release-assets.githubusercontent.com/github-production-release-asset/987654321/asset-uuid?sig=opaque&jwt=opaque&response-content-disposition=attachment%3B%20filename%3Dti-bundle.json",
		"https://release-assets.githubusercontent.com/github-production-release-asset/123456789/asset-uuid?sig=opaque&jwt=opaque&response-content-disposition=attachment%3B%20filename%3Ddifferent.json",
	} {
		target, _ := url.Parse(raw)
		if validFetchURL(target, base, "ti-bundle.json", source, "123456789") {
			t.Fatalf("unbound query accepted: %s", raw)
		}
	}
}

func TestUpdaterAcceptsOnlyCanonicalLatestToTaggedReleaseRedirect(t *testing.T) {
	base, _ := url.Parse("https://github.com/s1ns3nz0/ssc-init-ti/")
	source := "/s1ns3nz0/ssc-init-ti/releases/latest/download/ti-manifest.json"
	valid, _ := url.Parse("https://github.com/s1ns3nz0/ssc-init-ti/releases/download/ti-00000001/ti-manifest.json")
	if !validFetchURL(valid, base, "ti-manifest.json", source, "123456789") {
		t.Fatal("canonical latest-to-tagged release redirect rejected")
	}
	for _, raw := range []string{
		"https://github.com/s1ns3nz0/ssc-init-ti/releases/download/latest/ti-manifest.json",
		"https://github.com/s1ns3nz0/ssc-init-ti/releases/download/ti-1/ti-manifest.json",
		"https://github.com/s1ns3nz0/other/releases/download/ti-00000001/ti-manifest.json",
		"https://github.com/s1ns3nz0/ssc-init-ti/releases/download/ti-00000001/different.json",
	} {
		target, _ := url.Parse(raw)
		if validFetchURL(target, base, "ti-manifest.json", source, "123456789") {
			t.Fatalf("noncanonical tagged redirect accepted: %s", raw)
		}
	}
}

func TestUpdaterRejectsDifferentRepositoryIDRedirectBeforeNetwork(t *testing.T) {
	f, key := newUpdateFeed(t)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://release-assets.githubusercontent.com/github-production-release-asset/987654321/uuid/ti-manifest.json", http.StatusFound)
	})
	result := updaterForFeed(t, f, key).Update(context.Background())
	if result.ErrorCode != UpdateErrorRedirectRejected {
		t.Fatalf("result=%+v", result)
	}
}

func TestUpdaterFailsClosedWithoutCompiledRepositoryID(t *testing.T) {
	f, key := newUpdateFeed(t)
	hit := atomic.Bool{}
	f.server.Config.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) })
	u := updaterForFeed(t, f, key)
	u.RepositoryID = ""
	result := u.Update(context.Background())
	if result.Status != UpdateUnavailable || result.ErrorCode != UpdateErrorNetwork || hit.Load() {
		t.Fatalf("result=%+v hit=%v", result, hit.Load())
	}
}

func TestUpdaterRejectsSplitManifestAndBundleTrustForSameKeyID(t *testing.T) {
	f, manifestKey := newUpdateFeed(t)
	bundleKey, bundlePrivate := deterministicKey(t, "split bundle trust")
	f.bundleSig = ed25519.Sign(bundlePrivate, f.bundle)
	u := updaterForFeed(t, f, bundleKey)
	u.Keys = KeyRegistry{FamilyTI: {"ti-key": manifestKey}}
	result := u.Update(context.Background())
	if result.ErrorCode != UpdateErrorSignatureInvalid || result.Status != UpdateUnavailable {
		t.Fatalf("result=%+v", result)
	}
	status, _ := u.Manager.Status(context.Background())
	if status.Freshness != FreshnessMissing {
		t.Fatalf("split-trust bytes activated: %+v", status)
	}
}

func TestUpdaterSuccessMetadataSurvivesPostInstallCancellationAndConcurrentChange(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	ctx, cancel := context.WithCancel(context.Background())
	u.afterInstall = func() {
		cancel()
		raw := validTIBundleSequenceBytes("ti-key", 8)
		bundlePath, signaturePath := writeSignedBundleFixture(t, raw, f.privateKey)
		if _, err := u.Manager.Install(context.Background(), bundlePath, signaturePath); err != nil {
			t.Fatal(err)
		}
	}
	result := u.Update(ctx)
	wantDigest := sha256.Sum256(f.bundle)
	if result.Status != UpdateUpdated || result.Sequence != 7 || result.Digest != hex.EncodeToString(wantDigest[:]) || result.KeyID != "ti-key" || result.Freshness != FreshnessFresh {
		t.Fatalf("result=%+v", result)
	}
	status, _ := u.Manager.Status(context.Background())
	if status.Sequence != 8 {
		t.Fatalf("concurrent install did not run: %+v", status)
	}
}

func TestUpdaterRejectsThirdRedirectAndHTTPBodyIsNeverReturned(t *testing.T) {
	f, key := newUpdateFeed(t)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/s1ns3nz0/ssc-init-ti/releases/latest/download/ti-manifest.json":
			http.Redirect(w, r, "/s1ns3nz0/ssc-init-ti/releases/r1/ti-manifest.json", http.StatusFound)
		case "/s1ns3nz0/ssc-init-ti/releases/r1/ti-manifest.json":
			http.Redirect(w, r, "/s1ns3nz0/ssc-init-ti/releases/r2/ti-manifest.json", http.StatusFound)
		case "/s1ns3nz0/ssc-init-ti/releases/r2/ti-manifest.json":
			http.Redirect(w, r, "/s1ns3nz0/ssc-init-ti/releases/r3/ti-manifest.json", http.StatusFound)
		default:
			http.Error(w, "remote-super-secret", http.StatusTeapot)
		}
	})
	u := updaterForFeed(t, f, key)
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorRedirectRejected {
		t.Fatalf("redirect=%+v", got)
	}
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "remote-super-secret", http.StatusInternalServerError)
	})
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorNetwork || strings.Contains(fmt.Sprintf("%+v", got), "secret") {
		t.Fatalf("closed=%+v", got)
	}
}

func TestUpdaterMapsInternalTimeoutToNetworkAndCallerCancellationToCancellation(t *testing.T) {
	f, key := newUpdateFeed(t)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	u := updaterForFeed(t, f, key)
	client := *f.server.Client()
	client.Timeout = 20 * time.Millisecond
	u.Client = &client
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorNetwork {
		t.Fatalf("timeout=%+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := u.Update(ctx); got.ErrorCode != UpdateErrorCancellation {
		t.Fatalf("cancel=%+v", got)
	}
}

func TestUpdaterRejectsTamperedBundleSignature(t *testing.T) {
	f, key := newUpdateFeed(t)
	u := updaterForFeed(t, f, key)
	f.bundleSig[0] ^= 1
	if got := u.Update(context.Background()); got.ErrorCode != UpdateErrorSignatureInvalid || got.Status != UpdateUnavailable {
		t.Fatalf("signature=%+v", got)
	}
}
