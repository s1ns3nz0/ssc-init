package findingdisplay

import (
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestProjectAliasesAreDeterministicAcrossInputOrder(t *testing.T) {
	one := []model.Asset{{ID: "project:sha256:cccc", Type: model.AssetProject}, {ID: "tool:one", Type: model.AssetTool}, {ID: "project:sha256:aaaa", Type: model.AssetProject}, {ID: "project:sha256:bbbb", Type: model.AssetProject}}
	two := []model.Asset{one[3], one[2], one[0], one[1]}
	want := map[string]string{"project:sha256:aaaa": "project-1", "project:sha256:bbbb": "project-2", "project:sha256:cccc": "project-3"}
	if got := ProjectAliases(one); !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	if got := ProjectAliases(two); !reflect.DeepEqual(got, want) {
		t.Fatalf("shuffled=%v want=%v", got, want)
	}
}
