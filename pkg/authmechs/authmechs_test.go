package authmechs

import (
	"testing"

	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestRemoveMechsInDB(t *testing.T) {
	tests := []struct {
		name     string
		db       AuthDB
		mechList []string
		want     AuthDB
	}{
		{
			name:     "Test with empty db",
			db:       AuthDB{Mechanisms: []string{}},
			mechList: []string{"mech1", "mech2"},
			want:     AuthDB{Mechanisms: []string{}},
		},
		{
			name:     "Test with non-empty db and mechList",
			db:       AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList: []string{"mech1", "mech2"},
			want:     AuthDB{Mechanisms: []string{"mech3"}},
		},
		{
			name:     "Test with non-empty db and mechList where the removed mechs are at the end of the slice",
			db:       AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList: []string{"mech2", "mech3"},
			want:     AuthDB{Mechanisms: []string{"mech1"}},
		},
		{
			name:     "Test with non-empty db and empty mechList",
			db:       AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList: []string{},
			want:     AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
		},
		{
			name: "Test with real data on device updated from python Crypt",
			db: AuthDB{Mechanisms: []string{
				"builtin:prelogin",
				"builtin:policy-banner",
				"loginwindow:login",
				"builtin:login-begin",
				"builtin:reset-password,privileged",
				"loginwindow:FDESupport,privileged",
				"builtin:forward-login,privileged",
				"builtin:auto-login,privileged",
				"builtin:authenticate,privileged",
				"PKINITMechanism:auth,privileged",
				"builtin:login-success",
				"loginwindow:success",
				"HomeDirMechanism:login,privileged",
				"HomeDirMechanism:status",
				"MCXMechanism:login",
				"CryptoTokenKit:login",
				"loginwindow:done",
				"Crypt:Check,privileged",
				"Crypt:CryptGUI",
				"Crypt:Enablement,privileged",
			}},
			mechList: []string{"Crypt:Check,privileged", "Crypt:CryptGUI", "Crypt:Enablement,privileged"},
			want: AuthDB{Mechanisms: []string{
				"builtin:prelogin",
				"builtin:policy-banner",
				"loginwindow:login",
				"builtin:login-begin",
				"builtin:reset-password,privileged",
				"loginwindow:FDESupport,privileged",
				"builtin:forward-login,privileged",
				"builtin:auto-login,privileged",
				"builtin:authenticate,privileged",
				"PKINITMechanism:auth,privileged",
				"builtin:login-success",
				"loginwindow:success",
				"HomeDirMechanism:login,privileged",
				"HomeDirMechanism:status",
				"MCXMechanism:login",
				"CryptoTokenKit:login",
				"loginwindow:done",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeMechsInDB(tt.db, tt.mechList)

			assert.Equal(t, got, tt.want)
		})
	}
}

func TestSetMechsInDB(t *testing.T) {
	tests := []struct {
		name        string
		db          AuthDB
		mechList    []string
		indexMech   string
		indexOffset int
		add         bool
		want        AuthDB
	}{
		{
			name:        "Test with empty db",
			db:          AuthDB{Mechanisms: []string{}},
			mechList:    []string{"mech1", "mech2"},
			indexMech:   "mech1",
			indexOffset: 1,
			add:         true,
			want:        AuthDB{Mechanisms: []string{"mech1", "mech2"}},
		},
		{
			name:        "Test with non-empty db and mechList",
			db:          AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList:    []string{"mech4", "mech5"},
			indexMech:   "mech2",
			indexOffset: 1,
			add:         true,
			want:        AuthDB{Mechanisms: []string{"mech1", "mech2", "mech4", "mech5", "mech3"}},
		},
		{
			name:        "Test with non-empty db and empty mechList",
			db:          AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList:    []string{},
			indexMech:   "mech2",
			indexOffset: 1,
			add:         true,
			want:        AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
		},
		{
			name:        "Test with non-empty db, add is false",
			db:          AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList:    []string{"mech4", "mech3"},
			indexMech:   "mech2",
			indexOffset: 1,
			add:         false,
			want:        AuthDB{Mechanisms: []string{"mech1", "mech2"}},
		},
		{
			name:        "Test with non-empty db, mechList is empty, add is false",
			db:          AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList:    []string{},
			indexMech:   "mech2",
			indexOffset: 1,
			add:         false,
			want:        AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setMechsInDB(tt.db, tt.mechList, tt.indexMech, tt.indexOffset, tt.add)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		item  string
		want  int
	}{
		{
			name:  "Test with item in slice",
			slice: []string{"item1", "item2", "item3"},
			item:  "item2",
			want:  1,
		},
		{
			name:  "Test with item not in slice",
			slice: []string{"item1", "item2", "item3"},
			item:  "item4",
			want:  -1,
		},
		{
			name:  "Test with empty slice",
			slice: []string{},
			item:  "item1",
			want:  -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexOf(tt.slice, tt.item)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInsertMechsAtPosition(t *testing.T) {
	tests := []struct {
		name           string
		mechanisms     []string
		mechsToInsert  []string
		pos            int
		expectedResult []string
	}{
		{
			name:           "Insert at valid position",
			mechanisms:     []string{"mech1", "mech2", "mech3"},
			mechsToInsert:  []string{"mech4", "mech5"},
			pos:            1,
			expectedResult: []string{"mech1", "mech4", "mech5", "mech2", "mech3"},
		},
		{
			name:           "Insert at start",
			mechanisms:     []string{"mech1", "mech2", "mech3"},
			mechsToInsert:  []string{"mech4", "mech5"},
			pos:            0,
			expectedResult: []string{"mech4", "mech5", "mech1", "mech2", "mech3"},
		},
		{
			name:           "Insert at end",
			mechanisms:     []string{"mech1", "mech2", "mech3"},
			mechsToInsert:  []string{"mech4", "mech5"},
			pos:            3,
			expectedResult: []string{"mech1", "mech2", "mech3", "mech4", "mech5"},
		},
		{
			name:           "Insert at invalid position",
			mechanisms:     []string{"mech1", "mech2", "mech3"},
			mechsToInsert:  []string{"mech4", "mech5"},
			pos:            5,
			expectedResult: []string{"mech1", "mech2", "mech3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := insertMechsAtPosition(tt.mechanisms, tt.mechsToInsert, tt.pos)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGetAuthDB(t *testing.T) {
	tests := []struct {
		name   string
		want   AuthDB
		runner utils.MockCmdRunner
	}{
		{
			name: "Test with Crypt config",
			want: AuthDB{
				Class:   "evaluate-mechanisms",
				Comment: "Login mechanism based rule.  Not for general use, yet.",
				Created: 730353220.36463201,
				Mechanisms: []string{
					"builtin:prelogin",
					"builtin:policy-banner",
					"loginwindow:login",
					"builtin:login-begin",
					"builtin:reset-password,privileged",
					"loginwindow:FDESupport,privileged",
					"builtin:forward-login,privileged",
					"builtin:auto-login,privileged",
					"builtin:authenticate,privileged",
					"PKINITMechanism:auth,privileged",
					"builtin:login-success",
					"loginwindow:success",
					"HomeDirMechanism:login,privileged",
					"HomeDirMechanism:status",
					"MCXMechanism:login",
					"CryptoTokenKit:login",
					"Crypt:Check,privileged",
					"Crypt:CryptGUI",
					"Crypt:Enablement,privileged",
					"loginwindow:done",
				},
				Modified: 730407814.24742103,
				Shared:   true,
				Tries:    10000,
				Version:  11,
			},
			runner: utils.MockCmdRunner{
				Output: `<?xml version="1.0" encoding="UTF-8"?>
				<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
				<plist version="1.0">
				<dict>
						<key>class</key>
						<string>evaluate-mechanisms</string>
						<key>comment</key>
						<string>Login mechanism based rule.  Not for general use, yet.</string>
						<key>created</key>
						<real>730353220.36463201</real>
						<key>mechanisms</key>
						<array>
								<string>builtin:prelogin</string>
								<string>builtin:policy-banner</string>
								<string>loginwindow:login</string>
								<string>builtin:login-begin</string>
								<string>builtin:reset-password,privileged</string>
								<string>loginwindow:FDESupport,privileged</string>
								<string>builtin:forward-login,privileged</string>
								<string>builtin:auto-login,privileged</string>
								<string>builtin:authenticate,privileged</string>
								<string>PKINITMechanism:auth,privileged</string>
								<string>builtin:login-success</string>
								<string>loginwindow:success</string>
								<string>HomeDirMechanism:login,privileged</string>
								<string>HomeDirMechanism:status</string>
								<string>MCXMechanism:login</string>
								<string>CryptoTokenKit:login</string>
								<string>Crypt:Check,privileged</string>
								<string>Crypt:CryptGUI</string>
								<string>Crypt:Enablement,privileged</string>
								<string>loginwindow:done</string>
						</array>
						<key>modified</key>
						<real>730407814.24742103</real>
						<key>shared</key>
						<true/>
						<key>tries</key>
						<integer>10000</integer>
						<key>version</key>
						<integer>11</integer>
				</dict>
				</plist>`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &tt.runner
			r := utils.Runner{Runner: runner}
			got, err := getAuthDb(r)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckMechsInDB(t *testing.T) {
	tests := []struct {
		name        string
		db          AuthDB
		mechList    []string
		indexMech   string
		indexOffset int
		expected    bool
	}{
		{
			name:        "Test Case 1", // The case when the sequence is present before the indexMech
			db:          AuthDB{Mechanisms: []string{"mech2", "mech3", "mech1"}},
			mechList:    []string{"mech2", "mech3"},
			indexMech:   "mech1",
			indexOffset: 0,
			expected:    true,
		},
		{
			name:        "Test Case 2", // The case when the sequence is present after the indexMech
			db:          AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList:    []string{"mech2", "mech3"},
			indexMech:   "mech1",
			indexOffset: 0,
			expected:    false,
		},
		{
			name:        "Test Case 3",
			db:          AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList:    []string{"mech4", "mech5"},
			indexMech:   "mech3",
			indexOffset: 0,
			expected:    false,
		},
		{
			name:        "Test Case 4", // The case when the sequence is not present before the indexMech
			db:          AuthDB{Mechanisms: []string{"mech3", "mech1", "mech2"}},
			mechList:    []string{"mech2", "mech3"},
			indexMech:   "mech1",
			indexOffset: 0,
			expected:    false,
		},
		{
			name:        "Test Case 5", // The case when the sequence is present, but not in the correct order
			db:          AuthDB{Mechanisms: []string{"mech3", "mech2", "mech1"}},
			mechList:    []string{"mech2", "mech3"},
			indexMech:   "mech1",
			indexOffset: 0,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkMechsInDB(tt.db, tt.mechList, tt.indexMech, tt.indexOffset)
			assert.Equal(t, tt.expected, result)
		})
	}
}
