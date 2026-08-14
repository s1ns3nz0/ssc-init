package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func TestProductionKeysContainNoTestOrPrivateKeyMaterial(t *testing.T) {
	keys := ProductionKeys()
	if len(keys) != 1 || len(keys[FamilyTI]) != 1 {
		t.Fatalf("production trust registry shape=%v", keys)
	}
	want, err := hex.DecodeString("e75dda50f7c1836d086a9951b394cc7048bc76e222dbb0d42a9abc10c5a00d5e")
	if err != nil {
		t.Fatal(err)
	}
	if got := keys[FamilyTI]["ti-production-2026-01"]; !ed25519.PublicKey(got).Equal(ed25519.PublicKey(want)) {
		t.Fatalf("reviewed production key mismatch: %x", got)
	}
	for family, familyKeys := range keys {
		for keyID, key := range familyKeys {
			if strings.HasPrefix(strings.ToLower(keyID), "test") {
				t.Fatalf("production registry contains test key for %s", family)
			}
			if len(key) != ed25519.PublicKeySize {
				t.Fatalf("production registry contains non-public key material for %s", family)
			}
		}
	}
}

func TestProductionKeysReturnsDeepCopy(t *testing.T) {
	old := productionKeys
	original := make(ed25519.PublicKey, ed25519.PublicKeySize)
	original[0] = 7
	productionKeys = KeyRegistry{FamilyTI: {"ti-production-fixture": original}}
	t.Cleanup(func() { productionKeys = old })
	first := ProductionKeys()
	first[FamilyTI]["ti-production-fixture"][0] = 9
	first[FamilyTI]["mutation"] = make([]byte, ed25519.PublicKeySize)
	second := ProductionKeys()
	if second[FamilyTI]["ti-production-fixture"][0] != 7 {
		t.Fatal("caller byte mutation changed production trust")
	}
	if _, exists := second[FamilyTI]["mutation"]; exists {
		t.Fatal("caller mutation changed production trust")
	}
}
