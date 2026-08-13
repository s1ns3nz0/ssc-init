package version

import (
	"strconv"
	"strings"
)

const maxRangeBytes = 256

type parsedVersion struct {
	numbers    [4]uint64
	precision  int
	prerelease []string
}

func Match(assetID, value, expression string) (bool, bool) {
	if !supportedAsset(assetID) || value == "" || expression == "" || len(value) > 128 || len(expression) > maxRangeBytes || strings.ContainsRune(expression, 0) {
		return false, false
	}
	version, ok := parseVersion(value)
	if !ok {
		return false, false
	}
	alternatives := strings.Split(expression, "||")
	if len(alternatives) > 4 {
		return false, false
	}
	matched := false
	for _, alternative := range alternatives {
		value, valid := matchAlternative(version, alternative)
		if !valid {
			return false, false
		}
		matched = matched || value
	}
	return matched, true
}

func supportedAsset(assetID string) bool {
	for _, prefix := range []string{"pkg:npm/", "pkg:pypi/", "pkg:go/", "pkg:golang/", "pkg:cargo/", "pkg:brew/"} {
		if strings.HasPrefix(assetID, prefix) {
			return true
		}
	}
	return false
}

func matchAlternative(version parsedVersion, expression string) (bool, bool) {
	fields := strings.Fields(strings.ReplaceAll(strings.TrimSpace(expression), ",", " "))
	if len(fields) == 0 || len(fields) > 16 {
		return false, false
	}
	for _, field := range fields {
		matched, valid := matchComparator(version, field)
		if !valid {
			return false, false
		}
		if !matched {
			return false, true
		}
	}
	return true, true
}

func matchComparator(version parsedVersion, raw string) (bool, bool) {
	if raw == "*" || raw == "x" || raw == "X" {
		return false, false
	}
	if strings.HasPrefix(raw, "^") {
		return matchWindow(version, strings.TrimPrefix(raw, "^"), true)
	}
	if strings.HasPrefix(raw, "~") {
		return matchWindow(version, strings.TrimPrefix(raw, "~"), false)
	}
	for _, wildcard := range []string{".x", ".X", ".*"} {
		if strings.HasSuffix(raw, wildcard) {
			return matchWildcard(version, strings.TrimSuffix(raw, wildcard))
		}
	}
	op := "="
	value := raw
	for _, candidate := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(raw, candidate) {
			op, value = candidate, strings.TrimPrefix(raw, candidate)
			break
		}
	}
	target, ok := parseVersion(value)
	if !ok {
		return false, false
	}
	comparison := compare(version, target)
	switch op {
	case "=":
		return comparison == 0, true
	case ">=":
		return comparison >= 0, true
	case "<=":
		return comparison <= 0, true
	case ">":
		return comparison > 0, true
	case "<":
		return comparison < 0, true
	default:
		return false, false
	}
}

func matchWindow(version parsedVersion, raw string, caret bool) (bool, bool) {
	lower, ok := parseVersion(raw)
	if !ok {
		return false, false
	}
	upper := lower
	upper.prerelease = nil
	if caret {
		switch {
		case lower.numbers[0] > 0:
			upper.numbers[0]++
			upper.numbers[1], upper.numbers[2], upper.numbers[3] = 0, 0, 0
		case lower.numbers[1] > 0:
			upper.numbers[1]++
			upper.numbers[2], upper.numbers[3] = 0, 0
		default:
			upper.numbers[2]++
			upper.numbers[3] = 0
		}
	} else {
		if lower.precision < 2 {
			upper.numbers[0]++
			upper.numbers[1], upper.numbers[2], upper.numbers[3] = 0, 0, 0
		} else {
			upper.numbers[1]++
			upper.numbers[2], upper.numbers[3] = 0, 0
		}
	}
	return compare(version, lower) >= 0 && compare(version, upper) < 0, true
}

func matchWildcard(version parsedVersion, prefix string) (bool, bool) {
	parts := strings.Split(prefix, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return false, false
	}
	for index, part := range parts {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil || version.numbers[index] != number {
			return false, err == nil
		}
	}
	return true, true
}

func parseVersion(raw string) (parsedVersion, bool) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if raw == "" || strings.ContainsAny(raw, " /\\") {
		return parsedVersion{}, false
	}
	if index := strings.IndexByte(raw, '+'); index >= 0 {
		raw = raw[:index]
	}
	var prerelease []string
	if index := strings.IndexByte(raw, '-'); index >= 0 {
		prerelease = strings.Split(raw[index+1:], ".")
		raw = raw[:index]
		for _, part := range prerelease {
			if part == "" || !identifier(part) {
				return parsedVersion{}, false
			}
		}
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return parsedVersion{}, false
	}
	result := parsedVersion{precision: len(parts), prerelease: prerelease}
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return parsedVersion{}, false
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return parsedVersion{}, false
		}
		result.numbers[index] = number
	}
	return result, true
}

func identifier(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'A' || character > 'Z' {
				if character < 'a' || character > 'z' {
					if character != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

func compare(left, right parsedVersion) int {
	for index := range left.numbers {
		if left.numbers[index] < right.numbers[index] {
			return -1
		}
		if left.numbers[index] > right.numbers[index] {
			return 1
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) > 0 {
		return 1
	}
	if len(left.prerelease) > 0 && len(right.prerelease) == 0 {
		return -1
	}
	for index := 0; index < len(left.prerelease) && index < len(right.prerelease); index++ {
		leftNumber, leftErr := strconv.ParseUint(left.prerelease[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(right.prerelease[index], 10, 64)
		if leftErr == nil && rightErr == nil {
			if leftNumber < rightNumber {
				return -1
			}
			if leftNumber > rightNumber {
				return 1
			}
			continue
		}
		if leftErr == nil {
			return -1
		}
		if rightErr == nil {
			return 1
		}
		if left.prerelease[index] < right.prerelease[index] {
			return -1
		}
		if left.prerelease[index] > right.prerelease[index] {
			return 1
		}
	}
	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}
	return 0
}
