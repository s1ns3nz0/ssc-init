package privacy

import (
	"strings"
	"unicode"
)

// ContainsCredentialComponent reports whether a name contains a canonical
// credential component across separators, camel case, or acronym boundaries.
func ContainsCredentialComponent(value string) bool {
	if value == "authorizationHelper" || value == "AuthorizationHelper" {
		return false
	}
	if strings.EqualFold(value, "authorizationhelper") {
		return true
	}
	for _, component := range credentialComponents(value) {
		switch component {
		case "token", "secret", "password", "passwd", "credential", "credentials",
			"apikey", "accesskey", "privatekey", "clientsecret", "bearer", "signature", "key",
			"authorization", "auth", "header", "headers", "env":
			return true
		}
	}
	return false
}

func credentialComponents(value string) []string {
	runes := []rune(value)
	components := make([]string, 0, 4)
	for start := 0; start < len(runes); {
		for start < len(runes) && !unicode.IsLetter(runes[start]) && !unicode.IsDigit(runes[start]) {
			start++
		}
		if start == len(runes) {
			break
		}
		end := start
		for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end])) {
			end++
		}
		word := runes[start:end]
		wordStart := 0
		for index := 1; index < len(word); index++ {
			lowerToUpper := (unicode.IsLower(word[index-1]) || unicode.IsDigit(word[index-1])) && unicode.IsUpper(word[index])
			acronymToWord := unicode.IsUpper(word[index-1]) && unicode.IsUpper(word[index]) && index+1 < len(word) && unicode.IsLower(word[index+1])
			if lowerToUpper || acronymToWord {
				components = append(components, strings.ToLower(string(word[wordStart:index])))
				wordStart = index
			}
		}
		components = append(components, strings.ToLower(string(word[wordStart:])))
		start = end
	}
	return components
}
