package projects

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseVSCodeWorkspaceAcceptsLocalFolderAndWorkspaceURIs(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		wantPath string
		wantKind candidateKind
	}{
		{
			name:     "folder",
			contents: `{"folder":"file:///Users/example/project"}`,
			wantPath: "/Users/example/project",
			wantKind: candidateFolder,
		},
		{
			name:     "percent decoded folder",
			contents: `{"folder":"file:///Users/example/Project%20Name"}`,
			wantPath: "/Users/example/Project Name",
			wantKind: candidateFolder,
		},
		{
			name:     "workspace file",
			contents: `{"workspace":"file:///Users/example/project.code-workspace"}`,
			wantPath: "/Users/example/project.code-workspace",
			wantKind: candidateWorkspaceFile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, kind, err := parseVSCodeWorkspace([]byte(test.contents))
			if err != nil {
				t.Fatal(err)
			}
			if path != test.wantPath || kind != test.wantKind {
				t.Fatalf("path=%q kind=%v", path, kind)
			}
		})
	}
}

func TestParseVSCodeWorkspaceRejectsUnsafeMetadataWithoutLeakingValues(t *testing.T) {
	secret := "do-not-leak-project-metadata"
	tests := []struct {
		name     string
		contents string
		wantErr  error
	}{
		{name: "duplicate key", contents: `{"folder":"file:///Users/example/project","folder":"file:///Users/` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "folder and workspace", contents: `{"folder":"file:///Users/` + secret + `","workspace":"file:///Users/example/project.code-workspace"}`, wantErr: errMetadataMalformed},
		{name: "trailing JSON", contents: `{"folder":"file:///Users/` + secret + `"}{}`, wantErr: errMetadataMalformed},
		{name: "authority", contents: `{"folder":"file://server/Users/` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "userinfo", contents: `{"folder":"file://user@/Users/` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "query", contents: `{"folder":"file:///Users/` + secret + `?token=secret"}`, wantErr: errMetadataMalformed},
		{name: "fragment", contents: `{"folder":"file:///Users/` + secret + `#fragment"}`, wantErr: errMetadataMalformed},
		{name: "remote scheme", contents: `{"folder":"vscode-remote://ssh-remote+example/Users/` + secret + `"}`, wantErr: errRemoteUnsupported},
		{name: "virtual filesystem scheme", contents: `{"folder":"vscode-vfs://remote/Users/` + secret + `"}`, wantErr: errRemoteUnsupported},
		{name: "http scheme", contents: `{"folder":"https://example.test/Users/` + secret + `"}`, wantErr: errRemoteUnsupported},
		{name: "relative path", contents: `{"folder":"file:relative/` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "noncanonical single slash URI", contents: `{"folder":"file:/Users/` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "noncanonical extra slash URI", contents: `{"folder":"file:////Users/` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "noncanonical dot path", contents: `{"folder":"file:///Users/example/../` + secret + `"}`, wantErr: errMetadataMalformed},
		{name: "NUL value", contents: `{"folder":"file:///Users/` + secret + `\u0000"}`, wantErr: errMetadataMalformed},
		{name: "control value", contents: `{"folder":"file:///Users/` + secret + `\u0001"}`, wantErr: errMetadataMalformed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseVSCodeWorkspace([]byte(test.contents))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("err=%v want sentinel=%v", err, test.wantErr)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked input: %q", err)
			}
		})
	}
}

func TestParseJetBrainsRecentAcceptsOnlyRecentProjectPathsInSourceOrder(t *testing.T) {
	contents := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<application>
  <component name="Unrelated"><option name="recentPaths"><list><option value="/ignored"/></list></option></component>
  <component name="RecentProjectsManager">
    <option name="recentPaths"><list>
      <option value="$USER_HOME$/Projects/one"/>
      <option value="~/Projects/two"/>
      <option value="/Users/example/Projects/three"/>
    </list></option>
    <option name="other"><list><option value="/ignored"/></list></option>
  </component>
  <component name="RecentDirectoryProjectsManager"><option name="recentPaths"><list><option value="$USER_HOME$/Projects/four"/></list></option></component>
</application>`)

	paths, err := parseJetBrainsRecent(contents)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"$USER_HOME$/Projects/one", "~/Projects/two", "/Users/example/Projects/three", "$USER_HOME$/Projects/four"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths=%q want=%q", paths, want)
	}
}

func TestParseJetBrainsRecentRejectsUnsafeOrUnexpectedXML(t *testing.T) {
	secret := "do-not-leak-recent-project"
	valid := func(value string) string {
		return `<application><component name="RecentProjectsManager"><option name="recentPaths"><list><option value="` + value + `"/></list></option></component></application>`
	}
	tests := []struct {
		name     string
		contents string
	}{
		{name: "relative path", contents: valid(`relative/` + secret)},
		{name: "URL", contents: valid(`file:///Users/` + secret)},
		{name: "unknown variable", contents: valid(`$OTHER_HOME$/` + secret)},
		{name: "DTD", contents: `<!DOCTYPE application [<!ENTITY xxe SYSTEM "file:///` + secret + `">]>` + valid(`&xxe;`)},
		{name: "directive", contents: `<!ELEMENT application ANY>` + valid(`/Users/`+secret)},
		{name: "entity", contents: valid(`/Users/&amp;` + secret)},
		{name: "processing instruction", contents: `<?bad ` + secret + `?>` + valid(`/Users/`+secret)},
		{name: "wrong nesting", contents: `<application><component name="RecentProjectsManager"><list><option value="/Users/` + secret + `"/></list></component></application>`},
		{name: "text in accepted hierarchy", contents: `<application><component name="RecentProjectsManager"><option name="recentPaths"><list>` + secret + `<option value="/Users/example/project"/></list></option></component></application>`},
		{name: "trailing text", contents: valid(`/Users/example/project`) + secret},
		{name: "too many tokens", contents: strings.Repeat(`<!--x-->`, 4097) + valid(`/Users/`+secret)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseJetBrainsRecent([]byte(test.contents))
			if !errors.Is(err, errMetadataMalformed) {
				t.Fatalf("err=%v want sentinel=%v", err, errMetadataMalformed)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked input: %q", err)
			}
		})
	}
}
