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
