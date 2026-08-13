package findingdisplay

import (
	"fmt"
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
		return "verified threat intelligence matched this asset"
	}
	return "additional local review rule matched"
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
