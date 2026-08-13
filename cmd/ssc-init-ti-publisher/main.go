// Command ssc-init-ti-publisher builds unsigned TI publication artifacts from
// explicit pinned local snapshots. Signing remains a separate CI operation.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/tipublish"
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ssc-init-ti-publisher", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var osvPaths, openSSFPaths stringList
	var osvLicense, osvBaseURL, openSSFLicense, openSSFBaseURL string
	var version, sequence, keyID, generatedAt, validFrom, validUntil, outputDirectory string
	flags.Var(&osvPaths, "osv-source", "absolute local OSV snapshot path (repeatable)")
	flags.StringVar(&osvLicense, "osv-license", "", "approved SPDX license for every OSV source")
	flags.StringVar(&osvBaseURL, "osv-base-url", "", "public HTTPS OSV record base")
	flags.Var(&openSSFPaths, "openssf-source", "absolute local OpenSSF snapshot path (repeatable)")
	flags.StringVar(&openSSFLicense, "openssf-license", "", "approved SPDX license for every OpenSSF source")
	flags.StringVar(&openSSFBaseURL, "openssf-base-url", "", "public HTTPS OpenSSF record base")
	flags.StringVar(&version, "version", "", "bundle version")
	flags.StringVar(&sequence, "sequence", "", "positive bundle sequence")
	flags.StringVar(&keyID, "key-id", "", "publication key id")
	flags.StringVar(&generatedAt, "generated-at", "", "RFC3339 generation time")
	flags.StringVar(&validFrom, "valid-from", "", "RFC3339 validity start")
	flags.StringVar(&validUntil, "valid-until", "", "RFC3339 validity end")
	flags.StringVar(&outputDirectory, "output-dir", "", "absolute existing output directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || len(osvPaths)+len(openSSFPaths) == 0 || !cleanAbsolute(outputDirectory) || !absolutePaths(osvPaths) || !absolutePaths(openSSFPaths) {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	sequenceValue, err := strconv.ParseUint(sequence, 10, 64)
	generatedTime, generatedErr := parseUTC(generatedAt)
	validFromTime, validFromErr := parseUTC(validFrom)
	validUntilTime, validUntilErr := parseUTC(validUntil)
	if err != nil || generatedErr != nil || validFromErr != nil || validUntilErr != nil {
		fmt.Fprintln(stderr, "invalid publication metadata")
		return 2
	}
	input := tipublish.Input{
		OSV:         sources(osvPaths, osvLicense, osvBaseURL),
		OpenSSF:     sources(openSSFPaths, openSSFLicense, openSSFBaseURL),
		Version:     version,
		Sequence:    sequenceValue,
		KeyID:       keyID,
		GeneratedAt: generatedTime,
		ValidFrom:   validFromTime,
		ValidUntil:  validUntilTime,
	}
	bundleBytes, report, err := tipublish.Build(input)
	if err != nil {
		fmt.Fprintln(stderr, "publication input is invalid")
		return 1
	}
	reportBytes, err := tipublish.EncodeReport(report)
	if err != nil {
		fmt.Fprintln(stderr, "attribution report cannot be encoded")
		return 1
	}
	bundlePath := filepath.Join(outputDirectory, "ti-bundle.json")
	reportPath := filepath.Join(outputDirectory, "attribution-report.json")
	if exists(bundlePath) || exists(reportPath) {
		fmt.Fprintln(stderr, "publication artifacts already exist")
		return 1
	}
	if err := writeExclusive(bundlePath, bundleBytes); err != nil {
		fmt.Fprintln(stderr, "publication artifacts cannot be written")
		return 1
	}
	if err := writeExclusive(reportPath, reportBytes); err != nil {
		_ = os.Remove(bundlePath)
		fmt.Fprintln(stderr, "publication artifacts cannot be written")
		return 1
	}
	fmt.Fprintf(stdout, "published sequence %d: %d records (%d malicious, %d vulnerable)\n", report.Sequence, report.Records, report.Malicious, report.Vulnerable)
	return 0
}

func sources(paths []string, license, baseURL string) []tipublish.Source {
	result := make([]tipublish.Source, len(paths))
	for index, path := range paths {
		result[index] = tipublish.Source{Path: path, License: license, PublicURLBase: baseURL}
	}
	return result
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("time must be UTC RFC3339")
	}
	return parsed, nil
}

func absolutePaths(paths []string) bool {
	for _, path := range paths {
		if !cleanAbsolute(path) {
			return false
		}
	}
	return true
}

func cleanAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

func writeExclusive(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	writeErr := func() error {
		defer file.Close()
		if _, err := file.Write(raw); err != nil {
			return err
		}
		return file.Sync()
	}()
	if writeErr != nil {
		_ = os.Remove(path)
	}
	return writeErr
}
