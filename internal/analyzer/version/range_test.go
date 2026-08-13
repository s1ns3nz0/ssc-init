package version

import "testing"

func TestMatchSupportsClosedPackageEcosystemsAndCommonRanges(t *testing.T) {
	tests := []struct {
		asset, version, expression string
		want                       bool
	}{
		{"pkg:npm/example@1.5.0", "1.5.0", ">=1.2.0 <2.0.0", true},
		{"pkg:cargo/example@2.1.0", "2.1.0", "^2.0.0", true},
		{"pkg:golang/example@v1.9.1", "v1.9.1", "~1.9.0", true},
		{"pkg:go/example.com/demo@v1.2.3", "v1.2.3", ">=1.0.0 <2.0.0", true},
		{"pkg:pypi/example@3.11.2", "3.11.2", ">=3.10,<3.11", false},
		{"pkg:brew/example@1.4.0", "1.4.0", "1.4.x", true},
		{"pkg:npm/example@2.0.0", "2.0.0", "<2.0.0 || >=3.0.0", false},
	}
	for _, test := range tests {
		got, supported := Match(test.asset, test.version, test.expression)
		if !supported || got != test.want {
			t.Errorf("Match(%q,%q,%q)=(%v,%v) want (%v,true)", test.asset, test.version, test.expression, got, supported, test.want)
		}
	}
}

func TestMatchRejectsMalformedAmbiguousAndUnboundedInput(t *testing.T) {
	for _, test := range []struct{ asset, version, expression string }{
		{"tool:x", "1.0.0", ">=1"},
		{"pkg:npm/x@latest", "latest", ">=1"},
		{"pkg:npm/x@1", "1.0.0", "*"},
		{"pkg:npm/x@1", "1.0.0", ">= nope"},
		{"pkg:npm/x@1", "1.0.0", string(make([]byte, 257))},
		{"pkg:npm/x@1", "1.0.0", ">=1.0.0 <2.0.0 garbage"},
	} {
		if matched, supported := Match(test.asset, test.version, test.expression); matched || supported {
			t.Errorf("unsafe input accepted: %+v => (%v,%v)", test, matched, supported)
		}
	}
}

func TestMatchOrdersPrereleasesBelowRelease(t *testing.T) {
	if matched, supported := Match("pkg:npm/x@1.0.0-beta.1", "1.0.0-beta.1", ">=1.0.0"); !supported || matched {
		t.Fatalf("matched=%v supported=%v", matched, supported)
	}
}

func TestMatchOSVExpressionsUseClosedEcosystemOrdering(t *testing.T) {
	tests := []struct {
		name, asset, version, expression string
		want                             bool
	}{
		{"npm numeric prerelease", "pkg:npm/example", "1.0.0-beta.2", "osv:ecosystem:>=1.0.0-beta.10", false},
		{"npm boundary", "pkg:npm/example", "1.0.0-beta.10", "osv:ecosystem:>=1.0.0-beta.10", true},
		{"PyPI implicit post release", "pkg:pypi/example", "1.0", "osv:ecosystem:>=1.0-1", false},
		{"PyPI normalized boundary", "pkg:pypi/example", "1.0.post1", "osv:ecosystem:>=1.0-1", true},
		{"Go pseudo version", "pkg:golang/example.com/mod", "v1.2.3-0.20260101000000-aaaaaaaaaaaa", "osv:semver:>=1.2.3", false},
		{"Go release boundary", "pkg:golang/example.com/mod", "v1.2.3", "osv:semver:>=1.2.3", true},
		{"crates numeric prerelease", "pkg:cargo/example", "1.0.0-alpha.2", "osv:semver:>=1.0.0-alpha.10", false},
		{"crates boundary", "pkg:cargo/example", "1.0.0-alpha.10", "osv:semver:>=1.0.0-alpha.10", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matched, supported := Match(test.asset, test.version, test.expression)
			if !supported || matched != test.want {
				t.Fatalf("Match(%q,%q,%q)=(%v,%v), want (%v,true)", test.asset, test.version, test.expression, matched, supported, test.want)
			}
		})
	}
}

func TestOSVExpressionRejectsNonCanonicalSemVerAndWrongEcosystemSyntax(t *testing.T) {
	for _, test := range []struct {
		asset, rangeType, expression string
	}{
		{"pkg:npm/example", "SEMVER", ">=1.0"},
		{"pkg:npm/example", "SEMVER", ">=v1.0.0"},
		{"pkg:npm/example", "SEMVER", ">=1.0.0-01"},
		{"pkg:pypi/example", "ECOSYSTEM", ">=not-a-version"},
		{"pkg:maven/example", "ECOSYSTEM", ">=1.0.0"},
	} {
		if got, ok := OSVExpression(test.asset, test.rangeType, test.expression); ok || got != "" {
			t.Fatalf("OSVExpression(%q,%q,%q)=(%q,%v)", test.asset, test.rangeType, test.expression, got, ok)
		}
	}
}
