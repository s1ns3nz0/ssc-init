// Package packageid derives canonical package coordinates from collected and
// OSV package identities.
package packageid

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// Coordinate returns the version-independent canonical coordinate for a
// collected package asset. It rejects identities that cannot be established
// exactly from the PURL-like collector ID and asset fields.
func Coordinate(asset model.Asset) (string, bool) {
	if asset.Type != model.AssetPackage || unsafeName(asset.Name) || unsafeIdentity(asset.Version) {
		return "", false
	}
	purlType, encodedName, encodedVersion, ok := parseAssetID(asset.ID)
	if !ok {
		return "", false
	}
	name, ok := decodeName(encodedName)
	if !ok || name != asset.Name {
		return "", false
	}
	version, err := url.PathUnescape(encodedVersion)
	if err != nil || unsafeIdentity(version) || version != asset.Version {
		return "", false
	}
	return coordinate(purlType, name)
}

// FromOSV returns the version-independent canonical coordinate for an OSV
// ecosystem and package name. The ecosystem catalog is deliberately closed.
func FromOSV(ecosystem, name string) (string, bool) {
	switch ecosystem {
	case "npm":
		return coordinate("npm", name)
	case "PyPI":
		return coordinate("pypi", name)
	case "Go":
		return coordinate("go", name)
	case "crates.io":
		return coordinate("cargo", name)
	default:
		return "", false
	}
}

func parseAssetID(value string) (purlType, encodedName, encodedVersion string, ok bool) {
	if !strings.HasPrefix(value, "pkg:") || strings.ContainsAny(value, "?#") || containsControl(value) {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(value, "pkg:")
	purlType, rest, ok = strings.Cut(rest, "/")
	if !ok || !supportedPURLType(purlType) || strings.Count(rest, "@") != 1 {
		return "", "", "", false
	}
	encodedName, encodedVersion, ok = strings.Cut(rest, "@")
	if !ok || encodedName == "" || encodedVersion == "" {
		return "", "", "", false
	}
	return purlType, encodedName, encodedVersion, true
}

func coordinate(purlType, name string) (string, bool) {
	if unsafeName(name) {
		return "", false
	}
	segments := strings.Split(name, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || unsafeIdentity(segment) {
			return "", false
		}
	}
	switch purlType {
	case "npm":
		if len(segments) > 2 || len(segments) == 2 && !strings.HasPrefix(segments[0], "@") || len(segments) == 1 && strings.HasPrefix(segments[0], "@") {
			return "", false
		}
		name = strings.ToLower(name)
	case "pypi":
		if len(segments) != 1 {
			return "", false
		}
		name = normalizePyPI(name)
	case "go":
	case "cargo":
		if len(segments) != 1 {
			return "", false
		}
	default:
		return "", false
	}
	return "pkg:" + purlType + "/" + escapeName(name), true
}

func decodeName(value string) (string, bool) {
	parts := strings.Split(value, "/")
	decoded := make([]string, len(parts))
	for index, part := range parts {
		if part == "" {
			return "", false
		}
		value, err := url.PathUnescape(part)
		if err != nil || strings.Contains(value, "/") || unsafeIdentity(value) {
			return "", false
		}
		decoded[index] = value
	}
	return strings.Join(decoded, "/"), true
}

func supportedPURLType(value string) bool {
	switch value {
	case "npm", "pypi", "go", "cargo":
		return true
	default:
		return false
	}
}

func unsafeIdentity(value string) bool {
	return value == "" || strings.ContainsAny(value, "/\\?#") || containsControl(value)
}

func unsafeName(value string) bool {
	return value == "" || strings.HasPrefix(value, "/") || driveQualifiedPath(value) || strings.ContainsAny(value, "\\?#") || containsControl(value)
}

func driveQualifiedPath(value string) bool {
	return len(value) >= 3 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':' && value[2] == '/'
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func escapeName(value string) string {
	parts := strings.Split(value, "/")
	for index, part := range parts {
		parts[index] = strings.ReplaceAll(url.PathEscape(part), "@", "%40")
	}
	return strings.Join(parts, "/")
}

func normalizePyPI(value string) string {
	value = strings.ToLower(value)
	var normalized strings.Builder
	separator := false
	for _, character := range value {
		if character == '-' || character == '_' || character == '.' {
			if !separator {
				normalized.WriteByte('-')
			}
			separator = true
			continue
		}
		separator = false
		normalized.WriteRune(character)
	}
	return normalized.String()
}
