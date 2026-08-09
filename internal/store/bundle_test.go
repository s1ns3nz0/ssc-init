package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBundleIndexIsRebuildableAndIndependentOfSnapshots(t *testing.T) {
	store, err := Open(filepath.Join(privateTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	index := BundleIndex{Family: "ti", Sequence: 7, Version: "2026.08.10", Digest: strings.Repeat("a", 64), Freshness: "fresh", ValidUntil: now.Add(10 * 24 * time.Hour)}
	if err := store.ReplaceBundleIndex(context.Background(), index, now); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.BundleIndex(context.Background(), "ti")
	if err != nil || !ok || got != index {
		t.Fatalf("index=%+v ok=%v err=%v", got, ok, err)
	}
	if err := store.ClearBundleIndex(context.Background(), "ti"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.BundleIndex(context.Background(), "ti"); err != nil || ok {
		t.Fatalf("cleared index ok=%v err=%v", ok, err)
	}
}

func TestBundleAuditRejectsPrivateOrOpenVocabularyValues(t *testing.T) {
	store, err := Open(filepath.Join(privateTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, event := range []BundleAudit{
		{Family: "other", Action: "install", Sequence: 1, Digest: strings.Repeat("a", 64)},
		{Family: "ti", Action: "other", Sequence: 1, Digest: strings.Repeat("a", 64)},
		{Family: "ti", Action: "install", Sequence: 1, Digest: "GITHUB_TOKEN=raw-secret"},
	} {
		if err := store.RecordBundleAudit(context.Background(), event, time.Now()); err == nil {
			t.Fatalf("accepted audit=%+v", event)
		}
	}
}
