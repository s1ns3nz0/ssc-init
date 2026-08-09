package surfaces

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
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

func readVerifiedHomeFile(ctx context.Context, env collector.Environment, relative string) ([]byte, error) {
	rooted, ok := env.FS.(platform.RootedFileSystem)
	if !ok || rooted == nil {
		return nil, errGitConfigMalformed
	}
	root, err := rooted.OpenRoot(env.Home)
	if err != nil {
		return nil, errGitConfigMalformed
	}
	defer root.Close()
	components := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	parent := root
	if len(components) > 1 {
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			return nil, errGitConfigMalformed
		}
		defer parent.Close()
	}
	file, expected, opened, err := platform.OpenVerifiedFile(parent, components[len(components)-1])
	if err != nil {
		return nil, errGitConfigMalformed
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(&surfaceContextReader{ctx: ctx, reader: file}, maxSurfaceFileBytes+1))
	if err != nil || int64(len(contents)) > maxSurfaceFileBytes {
		return nil, errGitConfigMalformed
	}
	after, err := file.Stat()
	postName, postErr := parent.Lstat(components[len(components)-1])
	if err != nil || postErr != nil || after == nil || postName == nil || !os.SameFile(expected, postName) || !os.SameFile(opened, after) {
		return nil, errGitConfigMalformed
	}
	return contents, nil
}

type surfaceContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *surfaceContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
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
