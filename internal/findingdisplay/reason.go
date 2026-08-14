package findingdisplay

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

var ruleReasons = map[string]string{
	"ssc-init/mutable/provenance":       "provenance may change",
	"ssc-init/mutable/latest":           "the version uses a mutable latest reference",
	"ssc-init/mutable/unpinned-package": "package version is not pinned",
	"ssc-init/mutable/git-branch":       "the Git dependency follows a mutable branch",
	"ssc-init/mutable/remote-script":    "a remote script reference may change",
	"ssc-init/api/dynamic-execution":    "dynamic code execution behavior was observed",
	"ssc-init/api/process-launch":       "process launch behavior was observed",
	"ssc-init/api/credential-access":    "credential access behavior was observed",
	"ssc-init/api/outbound-network":     "outbound network behavior was observed",
	"ssc-init/content/obfuscation":      "obfuscated content was observed",
	"ssc-init/flow/credential-egress":   "credential access and outbound transfer behavior were observed together",
}

func Reason(finding model.Finding) string {
	rules := make(map[string]bool, len(finding.RuleIDs))
	for _, rule := range finding.RuleIDs {
		rules[rule] = true
	}
	if rules["ssc-init/mutable/unpinned-package"] && rules["ssc-init/mutable/provenance"] {
		return "package version is not pinned and provenance may change"
	}
	for _, rule := range reasonPriority {
		if rules[rule] {
			return ruleReasons[rule]
		}
	}
	if len(finding.IntelligenceIDs) > 0 {
		if finding.Verdict == model.VerdictKnownMalicious && hasMaliciousPackageAdvisory(finding) {
			return "verified malicious-package intelligence matched this exact package version"
		}
		if advisory := firstPublicAdvisory(finding); advisory != "" {
			return "this installed version is affected by " + advisory
		}
		return "verified threat intelligence matched this asset"
	}
	return "additional local review rule matched"
}

var publicAdvisoryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\ACVE-[0-9]{4}-[0-9]{4,}(?:#[0-9]{3})?\z`),
	regexp.MustCompile(`\AGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}(?:#[0-9]{3})?\z`),
	regexp.MustCompile(`\A(?:OSV|GO|PYSEC|RUSTSEC)-[0-9]{4}-[0-9]+(?:#[0-9]{3})?\z`),
	regexp.MustCompile(`\AMAL-[0-9]{4}-[0-9]+(?:#[0-9]{3})?\z`),
}

// PublicAdvisories returns only closed public source record identifiers.
func PublicAdvisories(finding model.Finding) string {
	seen := make(map[string]struct{}, len(finding.IntelligenceIDs))
	values := make([]string, 0, len(finding.IntelligenceIDs))
	for _, value := range finding.IntelligenceIDs {
		if len(value) == 0 || len(value) > 128 || !publicAdvisoryID(value) {
			continue
		}
		if child := strings.IndexByte(value, '#'); child >= 0 {
			value = value[:child]
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func publicAdvisoryID(value string) bool {
	for _, pattern := range publicAdvisoryPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func firstPublicAdvisory(finding model.Finding) string {
	advisories := PublicAdvisories(finding)
	if separator := strings.Index(advisories, ", "); separator >= 0 {
		return advisories[:separator]
	}
	return advisories
}

func hasMaliciousPackageAdvisory(finding model.Finding) bool {
	for _, value := range strings.Split(PublicAdvisories(finding), ", ") {
		if strings.HasPrefix(value, "MAL-") {
			return true
		}
	}
	return false
}

var reasonPriority = []string{
	"ssc-init/flow/credential-egress",
	"ssc-init/content/obfuscation",
	"ssc-init/api/dynamic-execution",
	"ssc-init/api/process-launch",
	"ssc-init/api/credential-access",
	"ssc-init/api/outbound-network",
	"ssc-init/mutable/remote-script",
	"ssc-init/mutable/latest",
	"ssc-init/mutable/git-branch",
	"ssc-init/mutable/unpinned-package",
	"ssc-init/mutable/provenance",
}

func Rules(finding model.Finding) string {
	var rules []string
	unknown := false
	for _, rule := range finding.RuleIDs {
		if _, known := ruleReasons[rule]; !known {
			unknown = true
			continue
		}
		rules = append(rules, strings.TrimPrefix(rule, "ssc-init/"))
	}
	if unknown {
		rules = append(rules, "additional/local-review")
	}
	if len(rules) == 0 {
		return "none recorded"
	}
	sort.Strings(rules)
	return strings.Join(rules, ", ")
}

func Evidence(finding model.Finding) string {
	if len(finding.EvidenceIDs) == 0 {
		return "none recorded"
	}
	if len(finding.EvidenceIDs) == 1 {
		return "1 linked item"
	}
	return fmt.Sprintf("%d linked items", len(finding.EvidenceIDs))
}

func Action(finding model.Finding) string {
	if finding.Verdict == model.VerdictKnownMalicious || finding.Verdict == model.VerdictBehaviorMalicious {
		return "REVIEW NOW"
	}
	return "INSPECT"
}
