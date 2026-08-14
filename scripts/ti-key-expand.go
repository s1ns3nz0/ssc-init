//go:build ignore

package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"

	"github.com/s1ns3nz0/ssc-init/scripts/internal/tikey"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	seed, err := io.ReadAll(io.LimitReader(os.Stdin, ed25519.SeedSize+1))
	if err != nil || len(seed) != ed25519.SeedSize {
		os.Exit(1)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	if err := tikey.WritePrivateExclusive(os.Args[1], key, nil); err != nil {
		fmt.Fprintln(os.Stderr, "private key cannot be written")
		os.Exit(1)
	}
}
