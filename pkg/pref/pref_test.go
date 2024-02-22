package pref

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPrefString(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping test on non-darwin system")
	}
	prefName := "testString"
	expectedValue := "testValue"
	p := New()
	defer p.Delete(prefName) //nolint:errcheck
	err := p.SetString(prefName, expectedValue)
	assert.NoError(t, err)

	value, err := p.GetString(prefName)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, value)
}

func TestGetPrefBool(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping test on non-darwin system")
	}
	prefName := "testBool"
	expectedValue := true
	p := New()
	defer p.Delete(prefName) //nolint:errcheck
	err := p.SetBool(prefName, expectedValue)
	assert.NoError(t, err)

	value, err := p.GetBool(prefName)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, value)
}

func TestGetPrefInt(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping test on non-darwin system")
	}
	prefName := "testInt"
	expectedValue := 123
	p := New()
	defer p.Delete(prefName) //nolint:errcheck
	err := p.SetInt(prefName, expectedValue)
	assert.NoError(t, err)

	value, err := p.GetInt(prefName)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, value)
}

func TestGetPrefArray(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping test on non-darwin system")
	}
	prefName := "testArray"
	expectedValue := []string{"value1", "value2", "value3"}
	p := New()
	defer p.Delete(prefName) //nolint:errcheck
	err := p.SetArray(prefName, expectedValue)
	assert.NoError(t, err)

	value, err := p.GetArray(prefName)
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, value)
}
