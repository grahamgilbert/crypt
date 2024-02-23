package utils

import (
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
	want := `key1 = "value1"
key2 = "value\"2"`

	got := BuildCurlConfigFile(d)
	assert.Equal(t, want, got)
}
