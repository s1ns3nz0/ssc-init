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
	return Updater{Manager: &m, Client: f.server.Client(), Base: f.base, Keys: KeyRegistry{FamilyTI: {"ti-key": publicKey}}, Now: testBundleNow}
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
