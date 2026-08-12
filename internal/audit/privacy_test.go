package audit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestValidateRejectsEverySensitiveMarker(t *testing.T) {
	for _, marker := range []string{"/Users/alice/private", "file:///Users/alice", "vscode-remote://ssh-remote+secret", "worktree-secret"} {
		record := validRecord()
		record.Run.Label = marker
		if Validate(record) == nil {
			t.Fatalf("accepted marker %q", marker)
		}
	}
}

func TestValidateRejectsEmbeddedPrivateMarkersWithoutRejectingDottedDisplayNames(t *testing.T) {
	for _, marker := range []string{"alice-macbook.local", "private workspace id", "workspace-secret", "see[/home/alice/private]", "endpoint 10.0.0.1:8443"} {
		record := validRecord()
		record.Run.Label = marker
		if err := Validate(record); err == nil {
			t.Fatalf("Validate accepted %q", marker)
		}
	}
	record := namedRecord()
	record.Inventory.Assets[0].Name = "socket.io"
	if err := Validate(record); err != nil {
		t.Fatalf("Validate rejected dotted display name: %v", err)
	}
}

func TestValidateRejectsPunctuationBypassedPrivateMarkers(t *testing.T) {
	for _, marker := range []string{"note,/home/alice/private", "note,/private-project/secret", "file:/Users/alice/private", "host{10.0.0.1:8443}", "env[API_KEY]=private", "cmd(--private-argument)"} {
		record := namedRecord()
		record.Inventory.Assets[0].Name = marker
		if err := Validate(record); err == nil {
			t.Fatalf("Validate accepted punctuated marker %q", marker)
		}
	}
}

func TestValidateRejectsRawSensitiveCategoriesInSafeTextField(t *testing.T) {
	for _, marker := range []string{"note/home/alice/private", "mailto:alice@example.com", "localhost:8080", "foo=private", "cmd(-p secret)"} {
		t.Run(marker, func(t *testing.T) {
			record := namedRecord()
			record.Inventory.Assets[0].Name = marker
			if err := Validate(record); err == nil {
				t.Fatalf("Validate accepted raw sensitive value %q in asset name", marker)
			}
		})
	}
}

func TestRedactPreservesDistinctCollectorTargetInstances(t *testing.T) {
	input := richInputRecord(time.UTC)
	input.Scan.Coverage[0].Targets = []model.TargetCoverage{
		{TargetID: "projects.discovery.git-worktrees", InstanceRef: "instance-a", Status: model.TargetPartial},
		{TargetID: "projects.discovery.git-worktrees", InstanceRef: "instance-b", Status: model.TargetPartial},
	}
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := Redact(record, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	targets := redacted.Coverage[0].Targets
	if len(targets) != 2 || targets[0].InstanceRef == "" || targets[0].InstanceRef == targets[1].InstanceRef {
		t.Fatalf("redacted target instances lost distinction: %+v", targets)
	}
}

func TestBuildTokenizesPrivateCollectorTargetInstances(t *testing.T) {
	input := richInputRecord(time.UTC)
	input.Scan.Coverage[0].Targets = []model.TargetCoverage{{
		TargetID: "mcp:vscode:workspace", InstanceRef: "JetBrains-IntelliJIdea2025.2-private-worktree", Status: model.TargetPartial,
	}}
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	instance := record.Coverage[0].Targets[0].InstanceRef
	if !instanceToken(instance) || strings.Contains(instance, "IntelliJ") || strings.Contains(instance, "worktree") {
		t.Fatalf("Build retained collector instance identity %q", instance)
	}
	redacted, err := Redact(record, [32]byte{10})
	if err != nil {
		t.Fatal(err)
	}
	if !exportToken(redacted.Coverage[0].Targets[0].InstanceRef) {
		t.Fatalf("Redact did not retokenize collector instance %q", redacted.Coverage[0].Targets[0].InstanceRef)
	}
}

func TestValidateRejectsUnsortedEvidenceCoverageErrors(t *testing.T) {
	record := graphRecord()
	record.EvidenceCoverage.Errors = []model.CoverageError{{Code: "target_rejected"}, {Code: "identity_changed"}}
	if err := Validate(record); err == nil {
		t.Fatal("Validate accepted unsorted evidence coverage errors")
	}
}

func TestCoverageErrorCatalogMatchesEveryProductionValueFlow(t *testing.T) {
	codes, unresolved, err := productionCoverageErrorCodes([]string{filepath.Join("..", "collector"), filepath.Join("..", "evidence"), filepath.Join("..", "inventory")})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("production error-code sinks have unresolved value flow: %s", strings.Join(unresolved, ", "))
	}
	if _, found := codes["remote_unsupported"]; !found {
		t.Fatal("producer value flow did not reach indirect remote_unsupported materialization")
	}
	ordered := make([]string, 0, len(codes))
	for code := range codes {
		ordered = append(ordered, code)
	}
	sort.Strings(ordered)
	for _, code := range ordered {
		if !validAuditErrorCode(code) {
			t.Errorf("production error code %q is absent from audit catalog", code)
		}
	}
}

func TestProductionCoverageErrorValueFlowFollowsConstantsVariablesAndMaterialization(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

const indirectCode = "constant_indirect"

type CoverageError struct { Code string }

func materialize(codes []string) []CoverageError {
	var errors []CoverageError
	for _, code := range codes {
		errors = append(errors, CoverageError{Code: code})
	}
	return errors
}

func produce() []CoverageError {
	variable := indirectCode
	return materialize([]string{variable})
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved synthetic value flow: %v", unresolved)
	}
	if _, found := codes["constant_indirect"]; !found {
		t.Fatalf("constant/variable/materialized code absent: %v", codes)
	}
}

var productionErrorCodePattern = regexp.MustCompile(`\A(?:[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+|stale|unsupported)\z`)

type sourceValueFlow struct {
	prefix       string
	packageNames map[string]struct{}
	topLevel     map[*ast.Object]string
	functions    map[string][]*sourceFunction
	direct       map[string]map[string]struct{}
	edges        map[string]map[string]struct{}
	sinks        map[string]string
	fieldCode    string
	nextSink     int
}

type sourceFunction struct {
	body         *ast.BlockStmt
	parameters   []string
	results      []string
	namedResults []string
}

func productionCoverageErrorCodes(roots []string) (map[string]struct{}, []string, error) {
	packageFiles := map[string][]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			packageFiles[filepath.Dir(path)] = append(packageFiles[filepath.Dir(path)], path)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	allCodes := map[string]struct{}{}
	var unresolved []string
	for directory, paths := range packageFiles {
		flow, err := newSourceValueFlow(directory, paths)
		if err != nil {
			return nil, nil, err
		}
		codes, missing := flow.resolveSinks()
		for code := range codes {
			allCodes[code] = struct{}{}
		}
		unresolved = append(unresolved, missing...)
	}
	sort.Strings(unresolved)
	return allCodes, unresolved, nil
}

func newSourceValueFlow(directory string, paths []string) (*sourceValueFlow, error) {
	files := make([]*ast.File, 0, len(paths))
	fileSet := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	flow := &sourceValueFlow{
		prefix:       filepath.ToSlash(directory),
		packageNames: map[string]struct{}{},
		topLevel:     map[*ast.Object]string{},
		functions:    map[string][]*sourceFunction{},
		direct:       map[string]map[string]struct{}{},
		edges:        map[string]map[string]struct{}{},
		sinks:        map[string]string{},
	}
	flow.fieldCode = flow.prefix + ":field:Code"
	for _, file := range files {
		for name, object := range file.Scope.Objects {
			flow.packageNames[name] = struct{}{}
			flow.topLevel[object] = flow.packageNode(name)
		}
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				flow.registerFunction(flow.packageNode(function.Name.Name), function.Type, function.Body)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.AssignStmt:
				flow.registerAssignedFunctionLiterals(value.Lhs, value.Rhs)
			case *ast.ValueSpec:
				names := make([]ast.Expr, len(value.Names))
				for index := range value.Names {
					names[index] = value.Names[index]
				}
				flow.registerAssignedFunctionLiterals(names, value.Values)
			}
			return true
		})
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if ok {
				flow.analyzeGeneralDeclaration(general)
			}
		}
	}
	functions := make([]*sourceFunction, 0, len(flow.functions))
	for _, candidates := range flow.functions {
		functions = append(functions, candidates...)
	}
	for _, function := range functions {
		flow.analyzeFunction(function)
	}
	return flow, nil
}

func (flow *sourceValueFlow) packageNode(name string) string {
	return flow.prefix + ":package:" + name
}

func (flow *sourceValueFlow) identifierNode(identifier *ast.Ident) string {
	if identifier == nil || identifier.Name == "_" {
		return ""
	}
	if node, found := flow.topLevel[identifier.Obj]; found {
		return node
	}
	if identifier.Obj != nil {
		return fmt.Sprintf("%s:object:%p", flow.prefix, identifier.Obj)
	}
	if _, found := flow.packageNames[identifier.Name]; found {
		return flow.packageNode(identifier.Name)
	}
	return flow.prefix + ":external:" + identifier.Name
}

func (flow *sourceValueFlow) registerAssignedFunctionLiterals(left, right []ast.Expr) {
	for index, expression := range right {
		literal, ok := expression.(*ast.FuncLit)
		if !ok || index >= len(left) {
			continue
		}
		identifier, ok := left[index].(*ast.Ident)
		if !ok {
			continue
		}
		flow.registerFunction(flow.identifierNode(identifier), literal.Type, literal.Body)
	}
}

func (flow *sourceValueFlow) registerFunction(node string, typeValue *ast.FuncType, body *ast.BlockStmt) {
	if node == "" || body == nil {
		return
	}
	function := &sourceFunction{body: body}
	function.parameters = flow.fieldNodes(typeValue.Params)
	function.results, function.namedResults = flow.resultNodes(node, typeValue.Results)
	flow.functions[node] = append(flow.functions[node], function)
}

func (flow *sourceValueFlow) fieldNodes(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var nodes []string
	for _, field := range fields.List {
		for _, name := range field.Names {
			nodes = append(nodes, flow.identifierNode(name))
		}
		if len(field.Names) == 0 {
			nodes = append(nodes, "")
		}
	}
	return nodes
}

func (flow *sourceValueFlow) resultNodes(functionNode string, fields *ast.FieldList) ([]string, []string) {
	if fields == nil {
		return nil, nil
	}
	var results, named []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for index := 0; index < count; index++ {
			results = append(results, fmt.Sprintf("%s:return:%d", functionNode, len(results)))
			if len(field.Names) != 0 {
				named = append(named, flow.identifierNode(field.Names[index]))
			} else {
				named = append(named, "")
			}
		}
	}
	return results, named
}

func (flow *sourceValueFlow) analyzeGeneralDeclaration(declaration *ast.GenDecl) {
	var previous []ast.Expr
	for _, specification := range declaration.Specs {
		value, ok := specification.(*ast.ValueSpec)
		if !ok {
			continue
		}
		expressions := value.Values
		if len(expressions) == 0 {
			expressions = previous
		} else {
			previous = expressions
		}
		for index, name := range value.Names {
			if len(expressions) == 0 {
				continue
			}
			expression := expressions[min(index, len(expressions)-1)]
			flow.linkExpression(flow.identifierNode(name), expression)
		}
	}
}

func (flow *sourceValueFlow) analyzeFunction(function *sourceFunction) {
	ast.Inspect(function.body, func(node ast.Node) bool {
		if literal, ok := node.(*ast.FuncLit); ok && literal.Body != function.body {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			flow.analyzeAssignment(value)
		case *ast.DeclStmt:
			if declaration, ok := value.Decl.(*ast.GenDecl); ok {
				flow.analyzeGeneralDeclaration(declaration)
			}
		case *ast.RangeStmt:
			flow.linkRangeVariable(value.Key, value.X)
			flow.linkRangeVariable(value.Value, value.X)
		case *ast.ReturnStmt:
			flow.analyzeReturn(function, value)
		case *ast.CallExpr:
			flow.connectCall(value)
		case *ast.CompositeLit:
			flow.analyzeCodeComposite(value)
		}
		return true
	})
}

func (flow *sourceValueFlow) analyzeAssignment(assignment *ast.AssignStmt) {
	if len(assignment.Rhs) == 1 && len(assignment.Lhs) > 1 {
		if call, ok := assignment.Rhs[0].(*ast.CallExpr); ok {
			if functions := flow.calledFunctions(call); len(functions) != 0 {
				for index, left := range assignment.Lhs {
					for _, function := range functions {
						if index < len(function.results) {
							flow.linkLeft(left, nil, function.results[index])
						}
					}
				}
				return
			}
		}
	}
	for index, left := range assignment.Lhs {
		if len(assignment.Rhs) == 0 {
			continue
		}
		right := assignment.Rhs[min(index, len(assignment.Rhs)-1)]
		flow.linkLeft(left, right, "")
	}
}

func (flow *sourceValueFlow) linkLeft(left ast.Expr, right ast.Expr, sourceNode string) {
	switch value := left.(type) {
	case *ast.Ident:
		destination := flow.identifierNode(value)
		if sourceNode != "" {
			flow.addEdge(destination, sourceNode)
		} else {
			flow.linkExpression(destination, right)
		}
	case *ast.IndexExpr:
		if destination := flow.baseIdentifierNode(value.X); destination != "" {
			flow.linkExpression(destination, value.Index)
			if sourceNode != "" {
				flow.addEdge(destination, sourceNode)
			} else {
				flow.linkExpression(destination, right)
			}
		}
	case *ast.SelectorExpr:
		if value.Sel.Name == "Code" {
			if sourceNode != "" {
				flow.addEdge(flow.fieldCode, sourceNode)
			} else {
				flow.linkExpression(flow.fieldCode, right)
			}
			flow.addSink(right, "assigned Code field")
		}
	}
}

func (flow *sourceValueFlow) baseIdentifierNode(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return flow.identifierNode(value)
	case *ast.IndexExpr:
		return flow.baseIdentifierNode(value.X)
	case *ast.SelectorExpr:
		return flow.baseIdentifierNode(value.X)
	}
	return ""
}

func (flow *sourceValueFlow) linkRangeVariable(expression ast.Expr, ranged ast.Expr) {
	identifier, ok := expression.(*ast.Ident)
	if ok {
		flow.linkExpression(flow.identifierNode(identifier), ranged)
	}
}

func (flow *sourceValueFlow) analyzeReturn(function *sourceFunction, statement *ast.ReturnStmt) {
	if len(statement.Results) == 0 {
		for index, named := range function.namedResults {
			if named != "" {
				flow.addEdge(function.results[index], named)
			}
		}
		return
	}
	if len(statement.Results) == 1 && len(function.results) > 1 {
		if call, ok := statement.Results[0].(*ast.CallExpr); ok {
			if calledFunctions := flow.calledFunctions(call); len(calledFunctions) != 0 {
				for index := range function.results {
					for _, called := range calledFunctions {
						if index < len(called.results) {
							flow.addEdge(function.results[index], called.results[index])
						}
					}
				}
				return
			}
		}
	}
	for index, result := range statement.Results {
		if index < len(function.results) {
			flow.linkExpression(function.results[index], result)
		}
	}
}

func (flow *sourceValueFlow) connectCall(call *ast.CallExpr) {
	for _, function := range flow.calledFunctions(call) {
		for index, argument := range call.Args {
			if index < len(function.parameters) && function.parameters[index] != "" {
				flow.linkExpression(function.parameters[index], argument)
			}
		}
	}
}

func (flow *sourceValueFlow) calledFunctions(call *ast.CallExpr) []*sourceFunction {
	switch value := call.Fun.(type) {
	case *ast.Ident:
		return flow.functions[flow.identifierNode(value)]
	case *ast.SelectorExpr:
		return flow.functions[flow.packageNode(value.Sel.Name)]
	}
	return nil
}

func (flow *sourceValueFlow) analyzeCodeComposite(composite *ast.CompositeLit) {
	typeName := ""
	switch value := composite.Type.(type) {
	case *ast.Ident:
		typeName = value.Name
	case *ast.SelectorExpr:
		typeName = value.Sel.Name
	}
	for _, element := range composite.Elts {
		keyed, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyed.Key.(*ast.Ident)
		if !ok || key.Name != "Code" {
			continue
		}
		flow.linkExpression(flow.fieldCode, keyed.Value)
		if typeName == "CoverageError" || typeName == "EvidenceError" {
			flow.addSink(keyed.Value, typeName)
		}
	}
}

func (flow *sourceValueFlow) addSink(expression ast.Expr, label string) {
	flow.nextSink++
	node := fmt.Sprintf("%s:sink:%d", flow.prefix, flow.nextSink)
	flow.sinks[node] = label
	flow.linkExpression(node, expression)
}

func (flow *sourceValueFlow) linkExpression(destination string, expression ast.Expr) {
	if destination == "" || expression == nil {
		return
	}
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			if decoded, err := strconv.Unquote(value.Value); err == nil {
				flow.addDirect(destination, decoded)
			}
		}
	case *ast.Ident:
		flow.addEdge(destination, flow.identifierNode(value))
	case *ast.ParenExpr:
		flow.linkExpression(destination, value.X)
	case *ast.UnaryExpr:
		flow.linkExpression(destination, value.X)
	case *ast.BinaryExpr:
		flow.linkExpression(destination, value.X)
		flow.linkExpression(destination, value.Y)
	case *ast.CallExpr:
		if identifier, ok := value.Fun.(*ast.Ident); ok && identifier.Name == "append" {
			for _, argument := range value.Args {
				flow.linkExpression(destination, argument)
			}
			return
		}
		if functions := flow.calledFunctions(value); len(functions) != 0 {
			for _, function := range functions {
				if len(function.results) != 0 {
					flow.addEdge(destination, function.results[0])
				}
			}
			return
		}
		for _, argument := range value.Args {
			flow.linkExpression(destination, argument)
		}
	case *ast.IndexExpr:
		flow.linkExpression(destination, value.X)
		flow.linkExpression(destination, value.Index)
	case *ast.SelectorExpr:
		if value.Sel.Name == "Code" {
			flow.addEdge(destination, flow.fieldCode)
		} else {
			flow.linkExpression(destination, value.X)
		}
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			if keyed, ok := element.(*ast.KeyValueExpr); ok {
				flow.linkExpression(destination, keyed.Value)
			} else {
				flow.linkExpression(destination, element)
			}
		}
	case *ast.KeyValueExpr:
		flow.linkExpression(destination, value.Value)
	case *ast.TypeAssertExpr:
		flow.linkExpression(destination, value.X)
	}
}

func (flow *sourceValueFlow) addDirect(node, value string) {
	if flow.direct[node] == nil {
		flow.direct[node] = map[string]struct{}{}
	}
	flow.direct[node][value] = struct{}{}
}

func (flow *sourceValueFlow) addEdge(destination, source string) {
	if destination == "" || source == "" || destination == source {
		return
	}
	if flow.edges[destination] == nil {
		flow.edges[destination] = map[string]struct{}{}
	}
	flow.edges[destination][source] = struct{}{}
}

func (flow *sourceValueFlow) resolveSinks() (map[string]struct{}, []string) {
	values := map[string]map[string]struct{}{}
	for node, direct := range flow.direct {
		values[node] = map[string]struct{}{}
		for value := range direct {
			values[node][value] = struct{}{}
		}
	}
	changed := true
	for changed {
		changed = false
		for destination, sources := range flow.edges {
			if values[destination] == nil {
				values[destination] = map[string]struct{}{}
			}
			for source := range sources {
				for value := range values[source] {
					if _, found := values[destination][value]; !found {
						values[destination][value] = struct{}{}
						changed = true
					}
				}
			}
		}
	}
	codes := map[string]struct{}{}
	var unresolved []string
	for node, label := range flow.sinks {
		found := false
		for value := range values[node] {
			if productionErrorCodePattern.MatchString(value) {
				codes[value] = struct{}{}
				found = true
			}
		}
		if !found {
			unresolved = append(unresolved, flow.prefix+":"+label)
		}
	}
	return codes, unresolved
}

func TestRedactRemovesNamesVersionsAndRetokenizesIDs(t *testing.T) {
	first, err := Redact(namedRecord(), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Redact(namedRecord(), [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if first.Inventory.Assets[0].Name != "" || first.Inventory.Assets[0].Version != "" {
		t.Fatal("identity display survived")
	}
	if first.Inventory.Assets[0].ID == second.Inventory.Assets[0].ID {
		t.Fatal("tokens correlate across salts")
	}
}

func TestRedactPreservesCountsStatusesAndRelationships(t *testing.T) {
	source := namedRecord()
	redacted, err := Redact(source, [32]byte{3})
	if err != nil || len(redacted.Inventory.Assets) != len(source.Inventory.Assets) || len(redacted.Inventory.Relationships) != len(source.Inventory.Relationships) || redacted.State != source.State {
		t.Fatalf("redacted=%+v err=%v", redacted, err)
	}
	if redacted.Inventory.Relationships[0].From != redacted.Inventory.Assets[0].ID || redacted.Inventory.Relationships[0].To != redacted.Inventory.Assets[1].ID {
		t.Fatal("relationships were not retokenized consistently")
	}
}

func TestRedactRewritesAnalyzerReferences(t *testing.T) {
	source := graphRecord()
	source.Inventory.AnalyzerFacts = []model.AnalyzerFact{{
		ID:          "fact:sha256:" + strings.Repeat("d", 64),
		AssetID:     source.Inventory.Assets[0].ID,
		EvidenceID:  source.Inventory.Evidence[0].ID,
		RuleID:      "rule-1",
		Category:    model.AnalyzerObfuscation,
		Confidence:  model.ConfidenceHigh,
		Occurrences: 1,
	}}
	redacted, err := Redact(source, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	fact := redacted.Inventory.AnalyzerFacts[0]
	if fact.ID == source.Inventory.AnalyzerFacts[0].ID || fact.AssetID != redacted.Inventory.Assets[0].ID || fact.EvidenceID == source.Inventory.AnalyzerFacts[0].EvidenceID {
		t.Fatalf("analyzer references were not consistently retokenized: %+v", fact)
	}
}

func TestValidateRedactedRejectsCanonicalIDsAndReferences(t *testing.T) {
	redacted, err := Redact(graphRecord(), [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Record){
		"asset ID":              func(record *Record) { record.Inventory.Assets[0].ID = "pkg:npm/private-package@1.2.3" },
		"relationship endpoint": func(record *Record) { record.Inventory.Relationships[0].From = "pkg:npm/private-package@1.2.3" },
		"observation ID":        func(record *Record) { record.Inventory.Observations[0].ID = "observation:private" },
		"project reference":     func(record *Record) { record.Inventory.Observations[0].ProjectID = "asset:private-project" },
		"evidence reference":    func(record *Record) { record.Inventory.Evidence[0].AssetID = "asset:private" },
		"finding reference":     func(record *Record) { record.Findings[0].AssetID = "asset:private" },
		"analyzer reference":    func(record *Record) { record.Inventory.AnalyzerFacts[0].EvidenceID = "evidence:private" },
		"coverage reference":    func(record *Record) { record.EvidenceCoverage.Targets[0].TargetID = "target:private" },
		"change reference":      func(record *Record) { record.Changes.Changes[0].EntityID = "asset:private" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record, err := clone(redacted)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if err := Validate(record); err == nil {
				t.Fatal("Validate accepted canonical/private identifier")
			}
		})
	}
}

func TestValidateRejectsPrivateMarkersAcrossSerializedModel(t *testing.T) {
	for _, marker := range []string{"alice-macbook.local", "private-code-workspace-id", "connected at /home/alice/private", "internal.example.test:8443", "ENV_VALUE=private", "--private-argument", "product-private-id", "git-worktree-private"} {
		t.Run(marker, func(t *testing.T) {
			record := graphRecord()
			record.Inventory.Assets[0].Metadata = map[string]string{"marker": marker}
			if err := Validate(record); err == nil {
				t.Fatalf("Validate accepted private marker %q", marker)
			}
		})
	}
}

func TestValidateRejectsInvalidNestedVocabularyAndGraphReferences(t *testing.T) {
	mutations := map[string]func(*Record){
		"collector status":  func(record *Record) { record.Coverage[0].Status = model.CoverageStatus("arbitrary") },
		"relationship kind": func(record *Record) { record.Inventory.Relationships[0].Kind = "arbitrary" },
		"change kind":       func(record *Record) { record.Changes.Changes[0].Kind = model.ChangeKind("arbitrary") },
		"evidence status":   func(record *Record) { record.Inventory.Evidence[0].Status = model.EvidenceStatus("arbitrary") },
		"missing asset":     func(record *Record) { record.Inventory.Relationships[0].To = "asset:missing" },
		"duplicate asset": func(record *Record) {
			record.Inventory.Assets = append(record.Inventory.Assets, record.Inventory.Assets[0])
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record := graphRecord()
			mutate(&record)
			record.Summary = summarize(record)
			if err := Validate(record); err == nil {
				t.Fatal("Validate accepted invalid nested model")
			}
		})
	}
}

func TestRedactRetokenizesProjectIDsInAllObservationCollections(t *testing.T) {
	redacted, err := Redact(graphRecord(), [32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	projectID := redacted.Inventory.Assets[1].ID
	if got := projectReference(redacted.Inventory.Observations); got != projectID {
		t.Fatalf("inventory ProjectID = %q, want %q", got, projectID)
	}
	if got := projectReference(redacted.Coverage[0].Observations); got != projectID {
		t.Fatalf("coverage ProjectID = %q, want %q", got, projectID)
	}
}

func projectReference(observations []model.Observation) string {
	for _, observation := range observations {
		if observation.ProjectID != "" {
			return observation.ProjectID
		}
	}
	return ""
}

func validRecord() Record {
	record, err := Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, validRun())
	if err != nil {
		panic(err)
	}
	return record
}

func namedRecord() Record {
	first := "asset:sha256:" + strings.Repeat("a", 64)
	second := "asset:sha256:" + strings.Repeat("b", 64)
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: first, Type: model.AssetPackage, Name: "private-package", Version: "1.2.3", SHA256: strings.Repeat("c", 64)},
			{ID: second, Type: model.AssetTool, Name: "private-tool", Version: "4.5.6"},
		},
		Relationships: []model.Relationship{{From: first, To: second, Kind: model.RelationshipUses}},
	}
	record, err := Build(model.ScanResult{Status: model.ScanComplete}, inventory, model.Delta{}, nil, validRun())
	if err != nil {
		panic(err)
	}
	return record
}

func graphRecord() Record {
	input := richInputRecord(time.UTC)
	project := input.Inventory.Assets[0].ID
	input.Inventory.Observations[0].ProjectID = project
	input.Scan.Coverage[0].Observations[0].ProjectID = project
	input.Inventory.AnalyzerFacts = []model.AnalyzerFact{{ID: "fact:one", AssetID: project, EvidenceID: input.Inventory.Evidence[0].ID, RuleID: "rule-1", Category: model.AnalyzerObfuscation, Confidence: model.ConfidenceHigh, Occurrences: 1}}
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		panic(err)
	}
	return record
}
