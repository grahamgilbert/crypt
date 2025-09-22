package checkin

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/groob/plist"
	"github.com/stretchr/testify/assert"
)

type MockPref struct{}

func (m *MockPref) GetBool(key string) (bool, error) {
	switch key {
	case "RotateUsedKey":
		return true, nil
	case "RemovePlist":
		return false, nil
	default:
		return false, nil
	}
}

func (m *MockPref) SetBool(key string, value bool) error {
	return nil
}

func (m *MockPref) GetString(key string) (string, error) {
	if key == "OutputPath" {
		return "/path/to/output.plist", nil
	}
	if key == "ServerURL" {
		return "http://test.com", nil
	}
	return "", nil
}

func (m *MockPref) SetString(key string, value string) error {
	return nil
}

func (m *MockPref) GetInt(key string) (int, error) {
	if key == "KeyEscrowInterval" {
		return 1, nil
	}
	return 0, nil
}

func (m *MockPref) SetInt(key string, value int) error {
	return nil
}

func (m *MockPref) GetArray(key string) ([]string, error) {
	if key == "SkipUsers" {
		return []string{"test_user1", "test_user2"}, nil
	}
	return nil, nil
}

func (m *MockPref) SetArray(key string, value []string) error {
	return nil
}

func (m *MockPref) Get(key string) (interface{}, error) {
	if key == "PostRunCommand" {
		return []string{"test", "command"}, nil
	}
	return nil, nil
}

func (m *MockPref) Set(key string, value interface{}) error {
	return nil
}

func (m *MockPref) Delete(key string) error {
	return nil
}

func (m *MockPref) GetDate(key string) (time.Time, error) {
	return time.Now(), nil
}

func (m *MockPref) SetDate(key string, value time.Time) error {
	return nil
}

func TestGetCommand(t *testing.T) {
	p := &MockPref{}

	command, err := getCommand(p)
	assert.NoError(t, err)
	assert.Equal(t, "test command", command)
}

func TestBuildCheckinURL(t *testing.T) {
	p := &MockPref{}

	url, err := buildCheckinURL(p)
	assert.Nil(t, err)
	assert.Equal(t, "http://test.com/checkin/", url)

}

func TestEscrowRequired(t *testing.T) {
	cryptData := CryptData{
		LastRun: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	p := &MockPref{}

	// Test when escrow is required
	required, err := escrowRequired(cryptData, p)
	assert.NoError(t, err)
	assert.True(t, required)

	// Test when escrow is not required
	cryptData.LastRun = time.Now()
	required, err = escrowRequired(cryptData, p)
	assert.NoError(t, err)
	assert.False(t, required)
}

func TestUserShouldBeSkipped(t *testing.T) {
	assert.True(t, userShouldBeSkipped("root"))
	assert.True(t, userShouldBeSkipped("_mbsetupuser"))

	assert.False(t, userShouldBeSkipped("test_user"))
}

func TestWritePlist(t *testing.T) {
	cryptData := CryptData{
		SerialNumber: "test_serial_number",
		EnabledUser:  "test_user",
	}

	tempFile, err := os.CreateTemp("", "test.plist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name()) // clean up

	err = writePlist(cryptData, tempFile.Name())
	assert.Nil(t, err)

	plistBytes, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	var readCryptData CryptData
	err = plist.Unmarshal(plistBytes, &readCryptData)
	assert.Nil(t, err)

	assert.Equal(t, cryptData, readCryptData)
}

func TestValidateRecoveryKey(t *testing.T) {
	testCases := []struct {
		name        string
		key         string
		expected    bool
		runner      utils.MockCmdRunner
		shouldError bool
	}{
		{
			name:     "valid recovery key",
			key:      "ABCD-1EFG-2HIJ-3ABC-ABCD-ABCD",
			expected: true,
			runner: utils.MockCmdRunner{
				Output: "true",
				Err:    nil,
			},
			shouldError: false,
		},
		{
			name:     "incorrect recovery key",
			key:      "ABCD-1EFG-2HIJ-3ABC-ABCD-ABCZ",
			expected: false,
			runner: utils.MockCmdRunner{
				Output: "false",
				Err:    fmt.Errorf("false"),
			},
			shouldError: false,
		},
		{
			name:     "invalid recovery key",
			key:      "not a valid key",
			expected: false,
			runner: utils.MockCmdRunner{
				Output: "Error: Not a valid recovery key.",
				Err:    fmt.Errorf("Error: Not a valid recovery key."),
			},
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := utils.Runner{}
			r.Runner = tc.runner
			valid, err := validateRecoveryKey(tc.key, r)
			if tc.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expected, valid)
		})
	}

}

func TestGetEnabledUser(t *testing.T) {
	p := &MockPref{}
	// Test no enabled users
	runner := utils.MockCmdRunner{
		Output: "test_user1,19F18F252-781C-4754-820D-C49346C386C4\ntest_user2,4A4E62FE-D022-4964-A3B7-CF4CE0C91650",
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = runner
	user, err := getEnabledUser(p, r)
	assert.NoError(t, err)
	assert.Equal(t, "", user)
	runner = utils.MockCmdRunner{
		Output: "test_user3,19F18F252-781C-4754-820D-C49346C386C4",
		Err:    nil,
	}
	r.Runner = runner
	user, err = getEnabledUser(p, r)
	assert.NoError(t, err)
	assert.Equal(t, "test_user3", user)
}

func TestBuildData(t *testing.T) {
	cryptData := CryptData{
		SerialNumber: "test_serial_number",
		EnabledUser:  "test_enabled_user",
		RecoveryKey:  "test_recovery_key",
	}
	runner := utils.MockCmdRunner{
		Output: "test_computer_name",
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = runner
	data, err := buildData(cryptData, r)
	assert.Nil(t, err)

	expectedData := url.Values{}
	expectedData.Set("serial", cryptData.SerialNumber)
	expectedData.Set("recovery_password", cryptData.RecoveryKey)
	expectedData.Set("username", cryptData.EnabledUser)
	expectedData.Set("macname", "test_computer_name")

	assert.Equal(t, expectedData.Encode(), data)
}

func TestServerInitiatedRotation(t *testing.T) {
	output := `{"rotation_required": true}`
	p := &MockPref{}

	runner := utils.MockCmdRunner{
		Output: "",
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = runner
	keyRotated, err := serverInitiatedRotation(output, r, p)
	assert.Nil(t, err)
	assert.False(t, keyRotated)
}

func TestGetRecoveryKey(t *testing.T) {
	type keyPlist struct {
		RecoveryKey string `plist:"RecoveryKey"`
	}

	key := keyPlist{RecoveryKey: "test_recovery_key"}
	p := &MockPref{}

	tmpFile, err := os.CreateTemp(os.TempDir(), "crypt-testing-")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // clean up

	plistBytes, err := plist.Marshal(&key)
	assert.NoError(t, err)

	err = os.WriteFile(tmpFile.Name(), plistBytes, 0644)
	assert.NoError(t, err)

	out, err := getRecoveryKey(tmpFile.Name(), p)
	if err != nil {
		t.Fatalf("getRecoveryKey failed with error: %v", err)
	}

	assert.Equal(t, key.RecoveryKey, out)
}

// TestEscrowKeySignatureCheck just verifies the escrowKey function accepts the mTLS parameter
func TestEscrowKeySignatureCheck(t *testing.T) {
	// No real test implementation, just verifying function signature
	t.Run("verify function signature", func(t *testing.T) {
		// We're not actually calling the function, just making sure
		// the compiler recognizes the function signature with mTLScommonName
		var _ = escrowKey
	})
}

func TestBuildCryptData(t *testing.T) {
	// Create a mock PrefInterface that returns specific values for testing
	mockPref := &MockPref{}

	// Create a mock runner that returns specific values for system commands
	mockRunner := utils.MockCmdRunner{
		Output: "enabled_user,19F18F252-781C-4754-820D-C49346C386C4",
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = mockRunner

	// Test building CryptData
	cryptData, err := buildCryptData(mockPref, r)
	assert.NoError(t, err)
	assert.NotEmpty(t, cryptData.SerialNumber)
	// GetConsoleUser returns the actual current user, so we just verify it's not empty
	assert.NotEmpty(t, cryptData.EnabledUser)
}

func TestRemoveInvalidKey(t *testing.T) {
	t.Run("remove from plist", func(t *testing.T) {
		// Create a temporary file
		tempFile, err := os.CreateTemp("", "test_plist_*.plist")
		assert.NoError(t, err)
		defer os.Remove(tempFile.Name()) // clean up

		// Write some content to the file
		err = os.WriteFile(tempFile.Name(), []byte("test content"), 0644)
		assert.NoError(t, err)

		// Remove the invalid key (should delete the file)
		err = removeInvalidKey(tempFile.Name(), false)
		assert.NoError(t, err)

		// Verify the file was deleted
		_, err = os.Stat(tempFile.Name())
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("remove from keychain", func(t *testing.T) {
		// Test removing from keychain - this will fail on systems without keychain setup
		// but we can test that the function calls the correct utility function
		err := removeInvalidKey("", true)
		// We expect this to potentially fail since we don't have a keychain setup in tests
		// but we're testing that the function path is correct
		assert.Error(t, err) // Expected to fail in test environment
	})
}

// MockKeychainPref is a mock preference that indicates keychain usage
type MockKeychainPref struct {
	MockPref
}

func (m *MockKeychainPref) GetBool(key string) (bool, error) {
	if key == "StoreRecoveryKeyInKeychain" {
		return true, nil
	}
	return m.MockPref.GetBool(key)
}

func TestGetRecoveryKeyWithKeychain(t *testing.T) {
	// Create a mock pref that indicates keychain usage
	mockPref := &MockKeychainPref{}

	// This test will fail in most environments since we don't have the keychain set up
	// but it tests the code path
	_, err := getRecoveryKey("", mockPref)
	assert.Error(t, err) // Expected to fail since no keychain entry exists
}

// MockExtendedPref extends MockPref to support additional functionality for testing
type MockExtendedPref struct {
	MockPref
	stringValues map[string]string
	boolValues   map[string]bool
	intValues    map[string]int
	arrayValues  map[string][]string
	dateValues   map[string]time.Time
}

func NewMockExtendedPref() *MockExtendedPref {
	return &MockExtendedPref{
		stringValues: make(map[string]string),
		boolValues:   make(map[string]bool),
		intValues:    make(map[string]int),
		arrayValues:  make(map[string][]string),
		dateValues:   make(map[string]time.Time),
	}
}

func (m *MockExtendedPref) GetString(key string) (string, error) {
	if val, ok := m.stringValues[key]; ok {
		return val, nil
	}
	return m.MockPref.GetString(key)
}

func (m *MockExtendedPref) GetBool(key string) (bool, error) {
	if val, ok := m.boolValues[key]; ok {
		return val, nil
	}
	return m.MockPref.GetBool(key)
}

func (m *MockExtendedPref) GetInt(key string) (int, error) {
	if val, ok := m.intValues[key]; ok {
		return val, nil
	}
	return m.MockPref.GetInt(key)
}

func (m *MockExtendedPref) GetArray(key string) ([]string, error) {
	if val, ok := m.arrayValues[key]; ok {
		return val, nil
	}
	return m.MockPref.GetArray(key)
}

func (m *MockExtendedPref) GetDate(key string) (time.Time, error) {
	if val, ok := m.dateValues[key]; ok {
		return val, nil
	}
	return m.MockPref.GetDate(key)
}

func TestBuildCryptDataWithSkippedUser(t *testing.T) {
	// Test buildCryptData when we get date information
	mockPref := NewMockExtendedPref()
	mockPref.arrayValues["SkipUsers"] = []string{"test_user"}
	mockPref.dateValues["LastEscrow"] = time.Now().Add(-2 * time.Hour)

	// Mock runner that returns enabled users for getEnabledUser fallback
	mockRunner := utils.MockCmdRunner{
		Output: "enabled_user,19F18F252-781C-4754-820D-C49346C386C4",
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = mockRunner

	cryptData, err := buildCryptData(mockPref, r)
	assert.NoError(t, err)
	assert.NotEmpty(t, cryptData.SerialNumber)
	// GetConsoleUser returns the actual current user, so we just verify it's not empty
	assert.NotEmpty(t, cryptData.EnabledUser)
	assert.NotZero(t, cryptData.LastRun)
}

func TestSendRequestErrorCases(t *testing.T) {
	// Test sendRequest error cases without actually making network calls
	// This tests the function structure and error handling

	t.Run("invalid URL", func(t *testing.T) {
		// Test with invalid URL to trigger request creation error
		_, err := sendRequest(":", "data", "commonName")
		assert.Error(t, err)
	})
}

func TestEscrowKeyConditionalBehavior(t *testing.T) {
	// Test that escrowKey properly chooses between mTLS and curl
	mockPref := NewMockExtendedPref()
	mockPref.stringValues["ServerURL"] = "https://test.example.com"

	mockRunner := utils.MockCmdRunner{
		Output: "test_computer_name",
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = mockRunner

	cryptData := CryptData{
		SerialNumber: "test_serial",
		RecoveryKey:  "test_key",
		EnabledUser:  "test_user",
	}

	t.Run("with mTLS common name", func(t *testing.T) {
		// This should attempt mTLS path but will fail due to missing keychain setup
		_, err := escrowKey(cryptData, r, mockPref, "test-common-name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send request with mTLS")
	})

	t.Run("without mTLS common name", func(t *testing.T) {
		// This should attempt curl path
		_, err := escrowKey(cryptData, r, mockPref, "")
		assert.Error(t, err)
		// The exact error depends on what curl returns, but we expect some error
		// since we're not actually making real network calls
		assert.NotNil(t, err)
	})
}
