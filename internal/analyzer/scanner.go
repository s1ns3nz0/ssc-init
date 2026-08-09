package analyzer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type Scanner struct{}

type lexicalRule struct {
	id         string
	category   model.AnalyzerCategory
	confidence model.Confidence
	tokens     []string
}

var lexicalRules = []lexicalRule{
	{"ssc-init/api/dynamic-execution", model.AnalyzerDynamicExecution, model.ConfidenceHigh, []string{"eval(", "exec(", "compile(", "new function("}},
	{"ssc-init/api/process-launch", model.AnalyzerProcessLaunch, model.ConfidenceHigh, []string{"child_process", "os/exec", "subprocess.", "runtime.getruntime().exec", "system("}},
	{"ssc-init/api/credential-access", model.AnalyzerCredentialAccess, model.ConfidenceMedium, []string{"process.env", "os.getenv(", "os.environ", "keychain", "credential"}},
	{"ssc-init/api/outbound-network", model.AnalyzerOutboundNetwork, model.ConfidenceMedium, []string{"fetch(", "http.newrequest", "requests.", "urllib.", "axios.", "xmlhttprequest"}},
}

func (Scanner) Analyze(ctx context.Context, content evidence.SealedContent) ([]model.AnalyzerFact, error) {
	raw, err := io.ReadAll(io.LimitReader(content, 1<<20+1))
	defer clear(raw)
	if err != nil || len(raw) > 1<<20 || ctx.Err() != nil {
		return nil, errorsNewAnalyzer()
	}
	masked := strings.ToLower(maskCommentsAndStrings(raw))
	var facts []model.AnalyzerFact
	for _, rule := range lexicalRules {
		occurrences := 0
		for _, token := range rule.tokens {
			occurrences += strings.Count(masked, token)
		}
		if occurrences == 0 {
			continue
		}
		digest := sha256.Sum256([]byte("ssc-init.analyzer.fact.v1\x00" + content.AssetID() + "\x00" + content.EvidenceID() + "\x00" + rule.id))
		facts = append(facts, model.AnalyzerFact{ID: fmt.Sprintf("analyzer:sha256:%x", digest), AssetID: content.AssetID(), EvidenceID: content.EvidenceID(), RuleID: rule.id, Category: rule.category, Confidence: rule.confidence, Occurrences: min(occurrences, 10_000)})
	}
	if occurrences := obfuscationOccurrences(raw); occurrences > 0 {
		ruleID := "ssc-init/content/obfuscation"
		digest := sha256.Sum256([]byte("ssc-init.analyzer.fact.v1\x00" + content.AssetID() + "\x00" + content.EvidenceID() + "\x00" + ruleID))
		facts = append(facts, model.AnalyzerFact{ID: fmt.Sprintf("analyzer:sha256:%x", digest), AssetID: content.AssetID(), EvidenceID: content.EvidenceID(), RuleID: ruleID, Category: model.AnalyzerObfuscation, Confidence: model.ConfidenceMedium, Occurrences: min(occurrences, 10_000)})
	}
	if occurrences := credentialEgressOccurrences(masked); occurrences > 0 {
		ruleID := "ssc-init/flow/credential-egress"
		digest := sha256.Sum256([]byte("ssc-init.analyzer.fact.v1\x00" + content.AssetID() + "\x00" + content.EvidenceID() + "\x00" + ruleID))
		facts = append(facts, model.AnalyzerFact{ID: fmt.Sprintf("analyzer:sha256:%x", digest), AssetID: content.AssetID(), EvidenceID: content.EvidenceID(), RuleID: ruleID, Category: model.AnalyzerCredentialEgress, Confidence: model.ConfidenceHigh, Occurrences: min(occurrences, 10_000)})
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	return facts, nil
}

func credentialEgressOccurrences(masked string) int {
	sources := tokenPositions(masked, []string{"process.env", "os.getenv(", "os.environ", "keychain", "credential"})
	sinks := tokenPositions(masked, []string{"fetch(", "http.newrequest", "requests.", "urllib.", "axios.", "xmlhttprequest"})
	count := 0
	for _, source := range sources {
		for _, sink := range sinks {
			if sink > source && sink-source <= 4096 {
				count++
				break
			}
		}
	}
	return count
}

func tokenPositions(value string, tokens []string) []int {
	var positions []int
	for _, token := range tokens {
		for offset := 0; offset < len(value); {
			index := strings.Index(value[offset:], token)
			if index < 0 {
				break
			}
			positions = append(positions, offset+index)
			offset += index + len(token)
		}
	}
	sort.Ints(positions)
	return positions
}

func errorsNewAnalyzer() error { return fmt.Errorf("analyzer input unavailable") }

func maskCommentsAndStrings(raw []byte) string {
	output := make([]byte, len(raw))
	copy(output, raw)
	const (
		normal = iota
		lineComment
		blockComment
		singleQuote
		doubleQuote
		backtick
	)
	state := normal
	for index := 0; index < len(output); index++ {
		current := output[index]
		switch state {
		case normal:
			switch {
			case current == '/' && index+1 < len(output) && output[index+1] == '/':
				output[index], output[index+1], state = ' ', ' ', lineComment
				index++
			case current == '/' && index+1 < len(output) && output[index+1] == '*':
				output[index], output[index+1], state = ' ', ' ', blockComment
				index++
			case current == '#':
				output[index], state = ' ', lineComment
			case current == '\'':
				output[index], state = ' ', singleQuote
			case current == '"':
				output[index], state = ' ', doubleQuote
			case current == '`':
				output[index], state = ' ', backtick
			}
		case lineComment:
			if current == '\n' {
				state = normal
			} else {
				output[index] = ' '
			}
		case blockComment:
			if current == '*' && index+1 < len(output) && output[index+1] == '/' {
				output[index], output[index+1], state = ' ', ' ', normal
				index++
			} else if current != '\n' {
				output[index] = ' '
			}
		case singleQuote, doubleQuote, backtick:
			quote := byte('\'')
			if state == doubleQuote {
				quote = '"'
			} else if state == backtick {
				quote = '`'
			}
			if current == '\\' && index+1 < len(output) {
				output[index], output[index+1] = ' ', ' '
				index++
				continue
			}
			output[index] = ' '
			if current == quote {
				state = normal
			}
		}
	}
	return string(output)
}
