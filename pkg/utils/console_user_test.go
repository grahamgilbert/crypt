package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConsoleUser(t *testing.T) {
	user, err := GetConsoleUser()
	assert.NoError(t, err)

	assert.NotEmpty(t, user)
}
