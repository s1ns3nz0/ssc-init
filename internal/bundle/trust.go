package bundle

import "crypto/ed25519"

// productionKeys contains only reviewed public verification keys. Private key
// material is held by the protected GitHub publication environment.
var productionKeys = KeyRegistry{
	FamilyTI: {
		"ti-production-2026-01": ed25519.PublicKey{
			0xe7, 0x5d, 0xda, 0x50, 0xf7, 0xc1, 0x83, 0x6d,
			0x08, 0x6a, 0x99, 0x51, 0xb3, 0x94, 0xcc, 0x70,
			0x48, 0xbc, 0x76, 0xe2, 0x22, 0xdb, 0xb0, 0xd4,
			0x2a, 0x9a, 0xbc, 0x10, 0xc5, 0xa0, 0x0d, 0x5e,
		},
	},
}

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
