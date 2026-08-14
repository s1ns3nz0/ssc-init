//go:build ignore

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	seed, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		os.Exit(1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if err := os.WriteFile(os.Args[2], key, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "private key cannot be written")
		os.Exit(1)
	}
	for i := range key {
		key[i] = 0
	}
}
