package utils

import (
	"errors"
	"testing"
)

func TestGetComputerName(t *testing.T) {
	testCases := []struct {
		name   string
		output string
		err    error
		want   string
	}{
		{
			name:   "successful command execution",
			output: "test-computer-name",
			err:    nil,
			want:   "test-computer-name",
		},
		{
			name:   "command execution error",
			output: "",
			err:    errors.New("command execution error"),
			want:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &MockCmdRunner{
				Output: tc.output,
				Err:    tc.err,
			}

			r := Runner{
				Runner: runner,
			}

			got, err := GetComputerName(r)
			if err != nil && err.Error() != tc.err.Error() {
				t.Errorf("GetComputerName() error = %v, wantErr %v", err, tc.err)
				return
			}
			if got != tc.want {
				t.Errorf("GetComputerName() = %v, want %v", got, tc.want)
			}
		})
	}
}
