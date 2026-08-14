//go:build ti_acceptance

package main

// This file is compiled only by the isolated end-to-end acceptance test. It is
// deliberately absent from every normal/release build and exposes no CLI flag
// or configuration-file surface.

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"os"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
)

func init() {
	baseURL := os.Getenv("SSC_INIT_ACCEPTANCE_TI_BASE")
	repositoryID := os.Getenv("SSC_INIT_ACCEPTANCE_TI_REPOSITORY_ID")
	keyID := os.Getenv("SSC_INIT_ACCEPTANCE_TI_KEY_ID")
	publicKey, err := base64.StdEncoding.DecodeString(os.Getenv("SSC_INIT_ACCEPTANCE_TI_PUBLIC_KEY"))
	certificate, certificateErr := os.ReadFile(os.Getenv("SSC_INIT_ACCEPTANCE_TI_CA"))
	roots := x509.NewCertPool()
	if baseURL == "" || repositoryID == "" || keyID == "" || err != nil || len(publicKey) != ed25519.PublicKeySize || certificateErr != nil || !roots.AppendCertsFromPEM(certificate) {
		return
	}
	bundleKeysForRun = bundle.KeyRegistry{bundle.FamilyTI: {keyID: ed25519.PublicKey(append([]byte(nil), publicKey...))}}
	productionTIConfigForRun = func() (string, string) { return baseURL, repositoryID }
	productionTIHTTPClientForRun = func() *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	}
}
