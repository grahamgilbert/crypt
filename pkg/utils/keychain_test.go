//go:build darwin
// +build darwin

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeychainFunctionality(t *testing.T) {
	// Note: These tests interact with the actual macOS keychain
	// They may fail in CI environments that don't have keychain access

	const testSecret = "test-recovery-key-12345"

	t.Run("add and retrieve secret", func(t *testing.T) {
		// Clean up any existing test secret first
		_ = DeleteSecret() // Ignore error if nothing exists

		// Add a secret to keychain
		err := AddSecret(testSecret)
		if err != nil {
			t.Skipf("Skipping keychain test - keychain not available: %v", err)
		}

		// Retrieve the secret
		retrievedSecret, err := GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, testSecret, retrievedSecret)

		// Clean up
		err = DeleteSecret()
		assert.NoError(t, err)
	})

	t.Run("get nonexistent secret", func(t *testing.T) {
		// Clean up any existing secret first
		_ = DeleteSecret() // Ignore error if nothing exists

		// Try to get a secret that doesn't exist
		_, err := GetSecret()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not find")
	})

	t.Run("add empty secret", func(t *testing.T) {
		// Try to add an empty secret
		err := AddSecret("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret cannot be empty")
	})

	t.Run("add whitespace-only secret", func(t *testing.T) {
		// Try to add a whitespace-only secret
		err := AddSecret("   \n\t  ")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret cannot be empty")
	})

	t.Run("delete nonexistent secret", func(t *testing.T) {
		// Clean up any existing secret first
		_ = DeleteSecret() // Ignore error if nothing exists

		// Try to delete a secret that doesn't exist
		err := DeleteSecret()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete")
	})

	t.Run("update existing secret", func(t *testing.T) {
		// Clean up any existing test secret first
		_ = DeleteSecret() // Ignore error if nothing exists

		const firstSecret = "first-test-secret"
		const secondSecret = "second-test-secret"

		// Add first secret
		err := AddSecret(firstSecret)
		if err != nil {
			t.Skipf("Skipping keychain test - keychain not available: %v", err)
		}

		// Try to add second secret (should fail because item already exists)
		err = AddSecret(secondSecret)
		assert.Error(t, err)

		// Verify first secret is still there
		retrievedSecret, err := GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, firstSecret, retrievedSecret)

		// Clean up
		err = DeleteSecret()
		assert.NoError(t, err)
	})
}

func TestKeychainWithTrimming(t *testing.T) {
	// Test that secrets are properly trimmed before storage
	const secretWithWhitespace = "  test-secret-with-whitespace  \n"
	const expectedSecret = "test-secret-with-whitespace"

	t.Run("secret trimming", func(t *testing.T) {
		// Clean up any existing test secret first
		_ = DeleteSecret() // Ignore error if nothing exists

		// Add secret with whitespace
		err := AddSecret(secretWithWhitespace)
		if err != nil {
			t.Skipf("Skipping keychain test - keychain not available: %v", err)
		}

		// Retrieve and verify it was trimmed
		retrievedSecret, err := GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, expectedSecret, retrievedSecret)

		// Clean up
		err = DeleteSecret()
		assert.NoError(t, err)
	})
}
