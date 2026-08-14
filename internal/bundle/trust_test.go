package bundle

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestProductionKeysContainNoTestOrPrivateKeyMaterial(t *testing.T) {
	keys := ProductionKeys()
	if len(keys) != 0 {
		t.Fatal("production trust must remain empty until a reviewed public key is provisioned")
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
