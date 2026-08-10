package provenance

import (
	"regexp"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

var exactPythonVersionPattern = regexp.MustCompile(`(?i)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]+))?(?:[-_.]?dev[-_.]?[0-9]+)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

func pythonRecord(name, version string, mutable bool, hashes []string) (Record, bool) {
	normalized, ok := normalizePyPIName(name)
	if !ok {
		return Record{}, false
	}
	record, ok := packageRecord("pypi", normalized, version)
	if !ok {
		return Record{}, false
	}
	unique, valid := distinctPythonSHA256(hashes)
	if !valid {
		return Record{}, false
	}
	exactVersion := exactPythonVersion(version)
	if mutable || !exactVersion {
		if !exactVersion {
			record.Version = ""
		}
		record.Provenance.Status = model.ProvenanceMutable
		record.Provenance.Integrity = ""
		return record, true
	}
	if len(unique) == 1 {
		record.Provenance.Status = model.ProvenanceImmutable
		record.Provenance.Integrity = "sha256:" + unique[0]
	} else {
		record.Provenance.Status = model.ProvenanceUnknown
		record.Provenance.Integrity = ""
	}
	return record, true
}

func normalizePyPIName(name string) (string, bool) {
	if !safeCoordinate(name) || !asciiLetterOrDigit(name[0]) || !asciiLetterOrDigit(name[len(name)-1]) {
		return "", false
	}
	var normalized strings.Builder
	normalized.Grow(len(name))
	separator := false
	for _, character := range []byte(name) {
		switch {
		case asciiLetterOrDigit(character):
			if separator {
				normalized.WriteByte('-')
				separator = false
			}
			if character >= 'A' && character <= 'Z' {
				character += 'a' - 'A'
			}
			normalized.WriteByte(character)
		case character == '.' || character == '_' || character == '-':
			separator = true
		default:
			return "", false
		}
	}
	return normalized.String(), true
}

func asciiLetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func exactPythonVersion(version string) bool {
	return exactPythonVersionPattern.MatchString(version)
}

func distinctPythonSHA256(hashes []string) ([]string, bool) {
	unique := make(map[string]struct{})
	for _, hash := range hashes {
		algorithm, digest, found := strings.Cut(hash, ":")
		if !found || !validPythonHashAlgorithm(algorithm) || !validPythonHashDigest(digest) {
			return nil, false
		}
		if algorithm == "sha256" {
			if !lowercaseSHA256(digest) {
				return nil, false
			}
			unique[digest] = struct{}{}
		}
	}
	values := make([]string, 0, len(unique))
	for digest := range unique {
		values = append(values, digest)
	}
	sort.Strings(values)
	return values, true
}

func validPythonHashAlgorithm(value string) bool {
	if value == "" || len(value) > 64 || !asciiLetterOrDigit(value[0]) || !asciiLetterOrDigit(value[len(value)-1]) {
		return false
	}
	for _, character := range []byte(value) {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' && character != '_' {
					return false
				}
			}
		}
	}
	return true
}

func validPythonHashDigest(value string) bool {
	if value == "" || len(value)%2 != 0 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
