package version

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

const osvExpressionPrefix = "osv:"
const osvOpenStartSentinel = "@start"

var pep440Pattern = regexp.MustCompile(`(?i)\Av?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)(?:[-_.]?(\d+))?)?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)(?:[-_.]?(\d+))?))?(?:[-_.]?(dev)(?:[-_.]?(\d+))?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\z`)

// OSVExpression validates an OSV selector against the declared range type and
// canonical package ecosystem, then tags it for ecosystem-aware matching.
func OSVExpression(assetID, rangeType, expression string) (string, bool) {
	kind := strings.ToLower(rangeType)
	if kind != "semver" && kind != "ecosystem" || !supportedOSVEcosystem(assetID) || expression == "" {
		return "", false
	}
	encoded := osvExpressionPrefix + kind + ":" + expression
	if len(encoded) > maxRangeBytes || !validOSVComparators(assetID, kind, expression) {
		return "", false
	}
	return encoded, true
}

// OSVOpenStart represents OSV's introduced:"0" sentinel as negative
// infinity while still requiring a valid collected ecosystem version.
func OSVOpenStart(assetID, rangeType string) (string, bool) {
	kind := strings.ToLower(rangeType)
	if kind != "semver" && kind != "ecosystem" || !supportedOSVEcosystem(assetID) {
		return "", false
	}
	return osvExpressionPrefix + kind + ":" + osvOpenStartSentinel, true
}

// OSVExact represents literal membership in affected[].versions. It does not
// use precedence equality, so identity-significant spellings stay distinct.
func OSVExact(assetID, version string) (string, bool) {
	if !validExactVersion(assetID, version) {
		return "", false
	}
	expression := osvExpressionPrefix + "exact:" + version
	if len(expression) > maxRangeBytes {
		return "", false
	}
	return expression, true
}

func matchOSVExpression(assetID, value, encoded string) (bool, bool) {
	rest := strings.TrimPrefix(encoded, osvExpressionPrefix)
	kind, expression, ok := strings.Cut(rest, ":")
	if !ok {
		return false, false
	}
	if kind == "exact" {
		return matchOSVExact(assetID, value, expression)
	}
	if kind != "semver" && kind != "ecosystem" {
		return false, false
	}
	if expression == osvOpenStartSentinel {
		_, valid := compareOSVVersion(assetID, kind, value, value)
		return valid, valid
	}
	if !validOSVComparators(assetID, kind, expression) {
		return false, false
	}
	fields := strings.Fields(expression)
	for _, field := range fields {
		operator, boundary, ok := osvComparator(field)
		if !ok {
			return false, false
		}
		comparison, ok := compareOSVVersion(assetID, kind, value, boundary)
		if !ok || !comparisonMatches(comparison, operator) {
			return false, ok
		}
	}
	return true, true
}

func matchOSVExact(assetID, candidate, listed string) (bool, bool) {
	if !validExactVersion(assetID, listed) || !validExactVersion(assetID, candidate) {
		return false, false
	}
	return candidate == listed, true
}

func validExactVersion(assetID, value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, " /\\") {
		return false
	}
	switch ecosystemOf(assetID) {
	case "npm", "cargo":
		_, ok := parseStrictSemver(value)
		return ok
	case "go":
		return semver.IsValid(goSemver(value))
	case "pypi":
		_, ok := parsePEP440(value)
		return ok
	default:
		return false
	}
}

func validOSVComparators(assetID, kind, expression string) bool {
	if strings.Contains(expression, osvOpenStartSentinel) {
		return false
	}
	fields := strings.Fields(expression)
	if len(fields) == 0 || len(fields) > 2 || strings.Contains(expression, ",") || strings.Contains(expression, "||") {
		return false
	}
	for _, field := range fields {
		_, boundary, ok := osvComparator(field)
		if !ok {
			return false
		}
		if _, ok := compareOSVVersion(assetID, kind, boundary, boundary); !ok {
			return false
		}
	}
	return true
}

func osvComparator(field string) (operator, boundary string, ok bool) {
	for _, candidate := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(field, candidate) {
			boundary = strings.TrimPrefix(field, candidate)
			return candidate, boundary, boundary != ""
		}
	}
	return "", "", false
}

func compareOSVVersion(assetID, kind, left, right string) (int, bool) {
	if kind == "semver" {
		left = semverForAsset(assetID, left)
		right = semverForAsset(assetID, right)
		leftVersion, leftOK := parseStrictSemver(left)
		rightVersion, rightOK := parseStrictSemver(right)
		if !leftOK || !rightOK {
			return 0, false
		}
		return compare(leftVersion, rightVersion), true
	}
	switch ecosystemOf(assetID) {
	case "npm", "cargo":
		leftVersion, leftOK := parseStrictSemver(left)
		rightVersion, rightOK := parseStrictSemver(right)
		if !leftOK || !rightOK {
			return 0, false
		}
		return compare(leftVersion, rightVersion), true
	case "go":
		left, right = goSemver(left), goSemver(right)
		if !semver.IsValid(left) || !semver.IsValid(right) {
			return 0, false
		}
		return semver.Compare(left, right), true
	case "pypi":
		leftVersion, leftOK := parsePEP440(left)
		rightVersion, rightOK := parsePEP440(right)
		if !leftOK || !rightOK {
			return 0, false
		}
		return comparePEP440(leftVersion, rightVersion), true
	default:
		return 0, false
	}
}

func semverForAsset(assetID, value string) string {
	if ecosystemOf(assetID) == "go" {
		return strings.TrimPrefix(value, "v")
	}
	return value
}

func goSemver(value string) string {
	if strings.HasPrefix(value, "v") {
		return value
	}
	return "v" + value
}

func parseStrictSemver(value string) (parsedVersion, bool) {
	if value == "" || strings.HasPrefix(value, "v") || strings.ContainsAny(value, " /\\") {
		return parsedVersion{}, false
	}
	core := value
	if index := strings.IndexByte(core, '+'); index >= 0 {
		if !validSemverIdentifiers(core[index+1:], false) {
			return parsedVersion{}, false
		}
		core = core[:index]
	}
	if index := strings.IndexByte(core, '-'); index >= 0 {
		if !validSemverIdentifiers(core[index+1:], true) {
			return parsedVersion{}, false
		}
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return parsedVersion{}, false
	}
	for _, part := range parts {
		if !decimalWithoutLeadingZero(part) {
			return parsedVersion{}, false
		}
	}
	return parseVersion(value)
}

func validSemverIdentifiers(value string, prerelease bool) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" || !identifier(part) || prerelease && allDigits(part) && len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}

func decimalWithoutLeadingZero(value string) bool {
	return value != "" && allDigits(value) && (len(value) == 1 || value[0] != '0')
}

func allDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func supportedOSVEcosystem(assetID string) bool { return ecosystemOf(assetID) != "" }

func ecosystemOf(assetID string) string {
	switch {
	case strings.HasPrefix(assetID, "pkg:npm/"):
		return "npm"
	case strings.HasPrefix(assetID, "pkg:pypi/"):
		return "pypi"
	case strings.HasPrefix(assetID, "pkg:go/"), strings.HasPrefix(assetID, "pkg:golang/"):
		return "go"
	case strings.HasPrefix(assetID, "pkg:cargo/"):
		return "cargo"
	default:
		return ""
	}
}

func comparisonMatches(comparison int, operator string) bool {
	switch operator {
	case "=":
		return comparison == 0
	case ">=":
		return comparison >= 0
	case "<=":
		return comparison <= 0
	case ">":
		return comparison > 0
	case "<":
		return comparison < 0
	default:
		return false
	}
}

type pep440Version struct {
	epoch   uint64
	release []uint64
	pre     *pep440Pre
	post    *uint64
	dev     *uint64
	local   []pep440Local
}

type pep440Pre struct {
	kind   int
	number uint64
}

type pep440Local struct {
	numeric bool
	number  uint64
	text    string
}

func parsePEP440(value string) (pep440Version, bool) {
	matches := pep440Pattern.FindStringSubmatch(strings.ToLower(value))
	if matches == nil {
		return pep440Version{}, false
	}
	result := pep440Version{}
	if matches[1] != "" {
		var ok bool
		result.epoch, ok = parseUint(matches[1])
		if !ok {
			return pep440Version{}, false
		}
	}
	for _, part := range strings.Split(matches[2], ".") {
		number, ok := parseUint(part)
		if !ok {
			return pep440Version{}, false
		}
		result.release = append(result.release, number)
	}
	if matches[3] != "" {
		kind := map[string]int{"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}[matches[3]]
		number, ok := optionalUint(matches[4])
		if !ok {
			return pep440Version{}, false
		}
		result.pre = &pep440Pre{kind: kind, number: number}
	}
	postValue := matches[5]
	if postValue == "" && matches[6] != "" {
		postValue = matches[7]
	}
	if matches[5] != "" || matches[6] != "" {
		number, ok := optionalUint(postValue)
		if !ok {
			return pep440Version{}, false
		}
		result.post = &number
	}
	if matches[8] != "" {
		number, ok := optionalUint(matches[9])
		if !ok {
			return pep440Version{}, false
		}
		result.dev = &number
	}
	if matches[10] != "" {
		for _, part := range regexp.MustCompile(`[-_.]`).Split(matches[10], -1) {
			if allDigits(part) {
				number, ok := parseUint(part)
				if !ok {
					return pep440Version{}, false
				}
				result.local = append(result.local, pep440Local{numeric: true, number: number})
			} else {
				result.local = append(result.local, pep440Local{text: part})
			}
		}
	}
	return result, true
}

func parseUint(value string) (uint64, bool) {
	number, err := strconv.ParseUint(value, 10, 64)
	return number, err == nil
}

func optionalUint(value string) (uint64, bool) {
	if value == "" {
		return 0, true
	}
	return parseUint(value)
}

func comparePEP440(left, right pep440Version) int {
	if compared := compareUint(left.epoch, right.epoch); compared != 0 {
		return compared
	}
	if compared := compareRelease(left.release, right.release); compared != 0 {
		return compared
	}
	if compared := comparePEP440Pre(left, right); compared != 0 {
		return compared
	}
	if compared := compareOptionalUint(left.post, right.post, -1); compared != 0 {
		return compared
	}
	if compared := compareOptionalUint(left.dev, right.dev, 1); compared != 0 {
		return compared
	}
	return compareLocal(left.local, right.local)
}

func compareRelease(left, right []uint64) int {
	length := len(left)
	if len(right) > length {
		length = len(right)
	}
	for index := 0; index < length; index++ {
		var leftValue, rightValue uint64
		if index < len(left) {
			leftValue = left[index]
		}
		if index < len(right) {
			rightValue = right[index]
		}
		if compared := compareUint(leftValue, rightValue); compared != 0 {
			return compared
		}
	}
	return 0
}

func comparePEP440Pre(left, right pep440Version) int {
	leftRank, rightRank := 0, 0
	if left.pre == nil {
		leftRank = 1
		if left.dev != nil && left.post == nil {
			leftRank = -1
		}
	}
	if right.pre == nil {
		rightRank = 1
		if right.dev != nil && right.post == nil {
			rightRank = -1
		}
	}
	if compared := compareInt(leftRank, rightRank); compared != 0 || left.pre == nil || right.pre == nil {
		return compared
	}
	if compared := compareInt(left.pre.kind, right.pre.kind); compared != 0 {
		return compared
	}
	return compareUint(left.pre.number, right.pre.number)
}

func compareOptionalUint(left, right *uint64, absentRank int) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return absentRank
	}
	if right == nil {
		return -absentRank
	}
	return compareUint(*left, *right)
}

func compareLocal(left, right []pep440Local) int {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if len(left) == 0 {
		return -1
	}
	if len(right) == 0 {
		return 1
	}
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index].numeric != right[index].numeric {
			if left[index].numeric {
				return 1
			}
			return -1
		}
		if left[index].numeric {
			if compared := compareUint(left[index].number, right[index].number); compared != 0 {
				return compared
			}
		} else if left[index].text < right[index].text {
			return -1
		} else if left[index].text > right[index].text {
			return 1
		}
	}
	return compareInt(len(left), len(right))
}

func compareUint(left, right uint64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
