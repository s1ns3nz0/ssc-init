//go:build ignore

package main

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"
)

type source struct {
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	SHA256    string `json:"sha256"`
	License   string `json:"license"`
	PublicURL string `json:"publicUrl"`
}
type evidence struct {
	SchemaVersion string   `json:"schemaVersion"`
	RetrievedAt   string   `json:"retrievedAt"`
	Sources       []source `json:"sources"`
}

func main() {
	if len(os.Args) != 11 || !validTime(os.Args[2]) {
		os.Exit(2)
	}
	sources := []source{{"osv", os.Args[3], os.Args[4], os.Args[5], os.Args[6]}, {"openssf-malicious-packages", os.Args[7], os.Args[8], os.Args[9], os.Args[10]}}
	for _, s := range sources {
		if !validSource(s) {
			os.Exit(2)
		}
	}
	raw, err := json.Marshal(evidence{"ssc-init.ti-source-provenance.v1", os.Args[2], sources})
	if err != nil {
		os.Exit(1)
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(os.Args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		os.Exit(1)
	}
	if _, err = file.Write(raw); err != nil || file.Sync() != nil || file.Close() != nil {
		os.Exit(1)
	}
}
func validTime(v string) bool {
	t, e := time.Parse(time.RFC3339, v)
	return e == nil && t.Location() == time.UTC
}
func validSource(s source) bool {
	if len(s.Revision) == 0 || len(s.Revision) > 256 || len(s.License) == 0 || len(s.License) > 64 || strings.ContainsAny(s.Revision+s.License, "\r\n\x00") {
		return false
	}
	d, e := hex.DecodeString(s.SHA256)
	if e != nil || len(d) != 32 || strings.ToLower(s.SHA256) != s.SHA256 {
		return false
	}
	u, e := url.Parse(s.PublicURL)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}
