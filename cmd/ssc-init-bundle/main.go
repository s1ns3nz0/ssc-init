// Command ssc-init-bundle validates and signs publication bundle bytes. It is
// a CI/publisher tool, not part of the user-facing ssc-init runtime.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) != 7 || args[0] != "sign" || args[1] != "--family" || args[3] != "--from" || args[5] != "--signature" ||
		args[2] != "ti" && args[2] != "policy" || !cleanAbsolute(args[4]) || !cleanAbsolute(args[6]) {
		fmt.Fprintln(os.Stderr, "invalid command arguments")
		return 2
	}
	seedEnvironment := "SSC_INIT_" + strings.ToUpper(args[2]) + "_BUNDLE_SIGNING_SEED_BASE64"
	seed, err := base64.StdEncoding.DecodeString(os.Getenv(seedEnvironment))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "bundle signing key is unavailable")
		return 1
	}
	raw, err := os.ReadFile(args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle document is unavailable")
		return 1
	}
	verifiedFamily, err := bundle.FamilyOf(raw)
	if err != nil || string(verifiedFamily) != args[2] {
		fmt.Fprintln(os.Stderr, "bundle document is invalid")
		return 1
	}
	signature, err := bundle.Sign(raw, ed25519.NewKeyFromSeed(seed))
	clear(seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle document is invalid")
		return 1
	}
	file, err := os.OpenFile(args[6], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle signature cannot be written")
		return 1
	}
	writeErr := func() error {
		defer file.Close()
		if _, err := file.Write(signature); err != nil {
			return err
		}
		return file.Sync()
	}()
	if writeErr != nil {
		_ = os.Remove(args[6])
		fmt.Fprintln(os.Stderr, "bundle signature cannot be written")
		return 1
	}
	return 0
}

func cleanAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}
