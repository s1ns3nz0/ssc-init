package platform

import "testing"

func TestOperationallySupported(t *testing.T) {
	tests := []struct {
		goos string
		want bool
	}{
		{goos: "darwin", want: true},
		{goos: "linux", want: false},
		{goos: "windows", want: false},
		{goos: "freebsd", want: false},
		{goos: "", want: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.goos, func(t *testing.T) {
			if got := OperationallySupported(testCase.goos); got != testCase.want {
				t.Fatalf("OperationallySupported(%q)=%t want=%t", testCase.goos, got, testCase.want)
			}
		})
	}
}
