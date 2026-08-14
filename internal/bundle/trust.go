package bundle

import "crypto/ed25519"

// productionKeys intentionally remains empty until a reviewed TI public key
// is committed. Production binaries therefore fail closed before provisioning.
var productionKeys = KeyRegistry{}

func ProductionKeys() KeyRegistry {
	result := make(KeyRegistry, len(productionKeys))
	for family, familyKeys := range productionKeys {
		copiedFamily := make(map[string]ed25519.PublicKey, len(familyKeys))
		for keyID, key := range familyKeys {
			copiedFamily[keyID] = append(ed25519.PublicKey(nil), key...)
		}
		result[family] = copiedFamily
	}
	return result
}
