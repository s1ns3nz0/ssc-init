package model

import "testing"

func TestDeveloperSurfaceAssetTypesAreStable(t *testing.T) {
	want := map[AssetType]string{
		AssetShellStartup: "shell-startup", AssetGitHook: "git-hook",
		AssetCredentialHelper: "credential-helper", AssetLaunchConfig: "launch-config",
		AssetProcess: "process", AssetListeningEndpoint: "listening-endpoint",
	}
	for assetType, value := range want {
		if string(assetType) != value {
			t.Fatalf("asset type=%q want=%q", assetType, value)
		}
	}
}
