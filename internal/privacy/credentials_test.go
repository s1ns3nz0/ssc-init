package privacy

import "testing"

func TestContainsCredentialComponentUsesCanonicalCamelAndAcronymVocabulary(t *testing.T) {
	for _, value := range []string{
		"key", "api-key", "githubToken", "githubTOKEN", "GitHubToken", "XAPIKey",
		"authorizationhelper", "AUTHORIZATIONHELPER", "clientSecret", "PRIVATEKey",
	} {
		t.Run("sensitive "+value, func(t *testing.T) {
			if !ContainsCredentialComponent(value) {
				t.Fatalf("credential component not recognized: %q", value)
			}
		})
	}
	for _, value := range []string{
		"authorizationHelper", "AuthorizationHelper", "githubTokenizer", "monkey", "keynote", "region",
	} {
		t.Run("safe "+value, func(t *testing.T) {
			if ContainsCredentialComponent(value) {
				t.Fatalf("safe name classified as credential: %q", value)
			}
		})
	}
}
