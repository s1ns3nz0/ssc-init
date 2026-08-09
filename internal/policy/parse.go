package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// Load parses and validates an ssc-init.policy.v1 document.
//
// Three refusals are structural rather than advisory:
//
//   - An unknown field is an error. A typo'd match field that parses to a
//     silently inert rule is worse than a refusal: the reader believes a rule
//     is protecting them and it is not.
//   - A duplicate object key is an error. encoding/json silently keeps the
//     last one, so {"enabled":true,"enabled":false} would load as disabled
//     with no signal.
//   - A rule without an explicit enabled flag is an error. Go's zero value
//     would make it false, which is the same silent-inertness failure as a
//     typo'd field; a rule's adoption state is the one thing an author must
//     state out loud.
//
// Every error names a location and a reason and never echoes a value: a rule
// identifier, a description, or a metadata value is author-supplied text that
// may itself be hostile, and the store's validation errors already hold this
// line. Where a location would have to quote the offending key, the key's
// ordinal position within its object is reported instead.
func Load(source []byte) (Document, error) {
	present, err := scanKeys(source)
	if err != nil {
		return Document{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		// scanKeys has already rejected malformed JSON, unknown keys, and
		// duplicate keys with a located, value-free message, so anything left
		// is a type mismatch. json's own text names Go types and sometimes the
		// offending bytes, so it is never surfaced.
		var typeError *json.UnmarshalTypeError
		if errors.As(err, &typeError) && typeError.Field != "" {
			return Document{}, fmt.Errorf("%s: wrong value type", typeError.Field)
		}
		return Document{}, errors.New("document: malformed JSON")
	}

	if err := validate(document, present); err != nil {
		return Document{}, err
	}
	if err := validateExceptions(document); err != nil {
		return Document{}, err
	}
	return document, nil
}

// ruleID is the closed identifier shape: lowercase, hyphen-separated, bounded.
var ruleID = regexp.MustCompile(`\A[a-z][a-z0-9-]{0,31}\z`)

var (
	documentKeys  = keySet("schemaVersion", "rules", "exceptions")
	ruleKeys      = keySet("id", "family", "enabled", "description", "match")
	matchKeys     = keySet("assetType", "assetName", "assetVersion", "host", "observationSource", "metadataEquals", "metadataContains", "evidenceStatus", "rungs")
	exceptionKeys = keySet("ruleId", "scope", "assetId", "digest", "projectId", "reason", "expiresAt")

	families   = keySet(string(FamilyShape), string(FamilyChange), string(FamilyPin))
	rungs      = keySet("NEW", "CHANGED", "UPGRADED", "REMOVED", "UNVERIFIED")
	assetTypes = keySet(
		string(model.AssetAgentPlugin), string(model.AssetSkill), string(model.AssetMCP),
		string(model.AssetIDEExtension), string(model.AssetPackage), string(model.AssetProject),
		string(model.AssetTool),
	)
	evidenceStatuses = keySet(
		string(model.EvidenceComplete), string(model.EvidencePartial), string(model.EvidenceOversize),
		string(model.EvidenceUnavailable), string(model.EvidenceUnsupported), string(model.EvidenceSkipped),
	)
)

func keySet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// allowedKeys returns the closed key set for the object at a normalized path
// ("rules[].match"), and whether the object accepts author-chosen keys — which
// only the two metadata maps do.
func allowedKeys(shape string) (map[string]bool, bool) {
	switch shape {
	case "":
		return documentKeys, false
	case "rules[]":
		return ruleKeys, false
	case "rules[].match":
		return matchKeys, false
	case "exceptions[]":
		return exceptionKeys, false
	}
	return nil, true
}

// scanKeys walks the token stream to reject malformed JSON, unknown keys, and
// duplicate keys — encoding/json reports none of the three with a usable,
// value-free location. It returns the set of keys present at each concrete
// path, which is how a missing enabled flag is told from an explicit false.
func scanKeys(source []byte) (map[string]map[string]bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	present := map[string]map[string]bool{}
	if err := scanValue(decoder, "", "", present, true); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("document: trailing content after the policy document")
	}
	return present, nil
}

var errMalformed = errors.New("document: malformed JSON")

func scanValue(decoder *json.Decoder, path, shape string, present map[string]map[string]bool, mustBeObject bool) error {
	token, err := decoder.Token()
	if err != nil {
		return errMalformed
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if mustBeObject {
			return errors.New("document: the policy document must be a JSON object")
		}
		return nil
	}

	switch delimiter {
	case '{':
		allowed, arbitrary := allowedKeys(shape)
		seen := map[string]bool{}
		for position := 0; decoder.More(); position++ {
			token, err := decoder.Token()
			if err != nil {
				return errMalformed
			}
			key, isKey := token.(string)
			if !isKey {
				return errMalformed
			}
			if seen[key] {
				return fmt.Errorf("%s: duplicate object key at position %d", location(path), position)
			}
			if !arbitrary && !allowed[key] {
				return fmt.Errorf("%s: unknown field at position %d", location(path), position)
			}
			seen[key] = true
			if err := scanValue(decoder, join(path, key), join(shape, key), present, false); err != nil {
				return err
			}
		}
		present[path] = seen
	case '[':
		if mustBeObject {
			return errors.New("document: the policy document must be a JSON object")
		}
		for index := 0; decoder.More(); index++ {
			element := fmt.Sprintf("%s[%d]", path, index)
			if err := scanValue(decoder, element, shape+"[]", present, false); err != nil {
				return err
			}
		}
	}
	// Consume the closing delimiter.
	if _, err := decoder.Token(); err != nil {
		return errMalformed
	}
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func location(path string) string {
	if path == "" {
		return "document"
	}
	return path
}

func validate(document Document, present map[string]map[string]bool) error {
	if document.SchemaVersion != SchemaVersion {
		return errors.New("schemaVersion: unsupported policy schema version")
	}
	identifiers := map[string]bool{}
	for index, rule := range document.Rules {
		at := fmt.Sprintf("rules[%d]", index)
		if !ruleID.MatchString(rule.ID) {
			return fmt.Errorf("%s.id: invalid rule identifier", at)
		}
		if identifiers[rule.ID] {
			return fmt.Errorf("%s.id: duplicate rule identifier", at)
		}
		identifiers[rule.ID] = true
		if !families[string(rule.Family)] {
			return fmt.Errorf("%s.family: unknown rule family", at)
		}
		if !present[at]["enabled"] {
			return fmt.Errorf("%s.enabled: missing enabled flag", at)
		}
		if strings.TrimSpace(rule.Description) == "" {
			return fmt.Errorf("%s.description: missing rule description", at)
		}
		if err := validateMatch(at, rule); err != nil {
			return err
		}
	}
	return nil
}

// matchField pairs a field's document name with how many values it carries, in
// a fixed order so that a document with several faults always reports the same
// one.
type matchField struct {
	name   string
	values int
}

func shapeFields(match *Match) []matchField {
	return []matchField{
		{"assetType", len(match.AssetType)},
		{"assetName", len(match.AssetName)},
		{"assetVersion", len(match.AssetVersion)},
		{"host", len(match.Host)},
		{"observationSource", len(match.ObservationSource)},
		{"metadataEquals", len(match.MetadataEquals)},
		{"metadataContains", len(match.MetadataContains)},
		{"evidenceStatus", len(match.EvidenceStatus)},
	}
}

func validateMatch(at string, rule Rule) error {
	if rule.Family == FamilyPin {
		// A pin rule matches on the presence or absence of a pin, not on
		// recorded facts, so a match here would silently do nothing.
		if rule.Match != nil {
			return fmt.Errorf("%s.match: a pin rule takes no match", at)
		}
		return nil
	}
	if rule.Match == nil {
		return fmt.Errorf("%s.match: missing match", at)
	}
	match := rule.Match

	shapeValues := 0
	for _, field := range shapeFields(match) {
		shapeValues += field.values
	}
	if rule.Family == FamilyChange {
		if len(match.Rungs) == 0 {
			return fmt.Errorf("%s.match.rungs: a change rule must name at least one rung", at)
		}
	} else {
		if len(match.Rungs) > 0 {
			return fmt.Errorf("%s.match.rungs: not valid for a shape rule", at)
		}
		if shapeValues == 0 {
			return fmt.Errorf("%s.match: a shape rule must test at least one fact", at)
		}
	}

	for _, rung := range match.Rungs {
		if !rungs[rung] {
			return fmt.Errorf("%s.match.rungs: unknown severity rung", at)
		}
	}
	for _, assetType := range match.AssetType {
		if !assetTypes[assetType] {
			return fmt.Errorf("%s.match.assetType: unknown asset type", at)
		}
	}
	for _, status := range match.EvidenceStatus {
		if !evidenceStatuses[status] {
			return fmt.Errorf("%s.match.evidenceStatus: unknown evidence status", at)
		}
	}
	for _, metadata := range []struct {
		name   string
		values map[string][]string
	}{{"metadataEquals", match.MetadataEquals}, {"metadataContains", match.MetadataContains}} {
		// Sorted, because map order is random and an error that moves is not
		// an error a reader can act on.
		for _, key := range slices.Sorted(maps.Keys(metadata.values)) {
			if strings.TrimSpace(key) == "" {
				return fmt.Errorf("%s.match.%s: empty metadata key", at, metadata.name)
			}
			if len(metadata.values[key]) == 0 {
				return fmt.Errorf("%s.match.%s: metadata key with no values", at, metadata.name)
			}
		}
	}
	return nil
}
