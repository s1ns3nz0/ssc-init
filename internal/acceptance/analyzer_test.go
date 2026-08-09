package acceptance

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestBoundedAnalyzerPersistsOnlyClosedFactsFromRealEntrypoint(t *testing.T) {
	home := t.TempDir()
	extension := filepath.Join(home, ".vscode", "extensions", "acme.analyzer-1.0.0")
	writeMatrixFile(t, filepath.Join(extension, "package.json"), `{"name":"analyzer","publisher":"acme","version":"1.0.0","main":"dist/main.js"}`)
	sentinel := "raw-source-must-not-survive"
	writeMatrixFile(t, filepath.Join(extension, "dist", "main.js"), `
const token = process.env.API_TOKEN;
fetch(endpoint, token);
child_process.exec(command);
eval(code);
// process.env.COMMENTED; fetch(commented); child_process.exec(commented); eval(commented);
const documentation = "`+sentinel+` process.env.QUOTED fetch(quoted) eval(quoted)";
`)

	result := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: filepath.Join(privateMatrixTempDir(t), "state.db"), scanID: "00000000-0000-4000-8000-0000000000b1",
	})
	if result.Scan.AnalyzerCoverage == nil || result.Scan.AnalyzerCoverage.Status != model.CoveragePartial || result.Scan.AnalyzerCoverage.FilesRead == 0 || !reflect.DeepEqual(result.Scan.AnalyzerCoverage.SkippedRules, []string{"tree-analysis-deferred"}) {
		t.Fatalf("analyzer coverage=%+v", result.Scan.AnalyzerCoverage)
	}
	want := map[model.AnalyzerCategory]int{
		model.AnalyzerCredentialAccess: 1, model.AnalyzerOutboundNetwork: 1, model.AnalyzerProcessLaunch: 1,
		model.AnalyzerDynamicExecution: 2, model.AnalyzerCredentialEgress: 1,
	}
	found := make(map[model.AnalyzerCategory]bool, len(want))
	for _, fact := range result.Inventory.AnalyzerFacts {
		if occurrences, ok := want[fact.Category]; ok {
			found[fact.Category] = true
			if fact.Occurrences != occurrences {
				t.Fatalf("commented or quoted twin affected fact: %+v", fact)
			}
		}
	}
	for category := range want {
		if !found[category] {
			t.Fatalf("missing analyzer category %q: %+v", category, result.Inventory.AnalyzerFacts)
		}
	}
	if bytes.Contains(result.Report, []byte(sentinel)) || strings.Contains(string(result.Report), home) {
		t.Fatalf("report leaked source or absolute home")
	}
}
