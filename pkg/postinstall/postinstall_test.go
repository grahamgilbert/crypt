package postinstall

import (
	"testing"

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
			name:     "Test with non-empty db and empty mechList",
			db:       AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
			mechList: []string{},
			want:     AuthDB{Mechanisms: []string{"mech1", "mech2", "mech3"}},
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
