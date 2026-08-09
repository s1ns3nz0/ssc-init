package surfaces

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errGitConfigMalformed = errors.New("git credential configuration is malformed")

func parseCredentialHelpers(contents []byte) ([]string, string, error) {
	if len(contents) > int(maxSurfaceFileBytes) || !utf8.Valid(contents) {
		return nil, "", errGitConfigMalformed
	}
	helpers := make(map[string]struct{})
	inGlobalCredential := false
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	scanner.Buffer(make([]byte, 4096), int(maxSurfaceFileBytes)+1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, "", errGitConfigMalformed
			}
			section := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			inGlobalCredential = strings.EqualFold(section, "credential")
			continue
		}
		if !inGlobalCredential {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "helper") {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			clear(helpers)
			continue
		}
		helper, ok := normalizedCredentialHelper(value)
		if !ok {
			return nil, "", errGitConfigMalformed
		}
		helpers[helper] = struct{}{}
	}
	if scanner.Err() != nil {
		return nil, "", errGitConfigMalformed
	}
	ordered := make([]string, 0, len(helpers))
	for helper := range helpers {
		ordered = append(ordered, helper)
	}
	sort.Strings(ordered)
	return ordered, credentialSemanticDigest(ordered), nil
}

func normalizedCredentialHelper(value string) (string, bool) {
	if strings.HasPrefix(value, "!") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "!"))
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}
	if strings.Contains(fields[0], "../") || strings.Contains(fields[0], `..\`) {
		return "", false
	}
	helper := filepath.Base(fields[0])
	helper = strings.TrimPrefix(helper, "git-credential-")
	if helper == "" || len(helper) > 128 {
		return "", false
	}
	for _, character := range helper {
		if unicode.IsControl(character) || !(unicode.IsLetter(character) || unicode.IsDigit(character) || strings.ContainsRune("._-", character)) {
			return "", false
		}
	}
	return strings.ToLower(helper), true
}

func credentialSemanticDigest(helpers []string) string {
	hasher := sha256.New()
	writeCredentialField(hasher, "ssc-init.git-credential.v1")
	for _, helper := range helpers {
		writeCredentialField(hasher, helper)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeCredentialField(hasher interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write([]byte(value))
}
