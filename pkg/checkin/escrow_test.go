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

	tmpFile, err := os.CreateTemp(os.TempDir(), "crypt-testing-")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // clean up

	plistBytes, err := plist.Marshal(&key)
	assert.NoError(t, err)

	err = os.WriteFile(tmpFile.Name(), plistBytes, 0644)
	assert.NoError(t, err)

	out, err := getRecoveryKey(tmpFile.Name())
	if err != nil {
		t.Fatalf("getRecoveryKey failed with error: %v", err)
	}

	assert.Equal(t, key.RecoveryKey, out)
}
