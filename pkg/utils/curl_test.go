package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurlEscape(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{input: `test"string`, want: `test\"string`},
		{input: `no_quotes_here`, want: `no_quotes_here`},
	}

	for _, tc := range testCases {
		got := curlEscape(tc.input)
		assert.Equal(t, tc.want, got)
	}
}

func TestBuildCurlConfigFile(t *testing.T) {
	d := map[string]string{
		"key1": `value1`,
		"key2": `value"2`,
	}
	expectedLines := []string{
		`key1 = "value1"`,
		`key2 = "value\"2"`,
	}

	got := BuildCurlConfigFile(d)
	gotLines := strings.Split(got, "\n")

	assert.Equal(t, len(expectedLines), len(gotLines), "Number of lines should match")
	for _, line := range expectedLines {
		assert.Contains(t, gotLines, line, "Output should contain the expected line")
	}
}
