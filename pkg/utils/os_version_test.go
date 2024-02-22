package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetOSVersion(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		err     error
		want    string
		wantErr bool
	}{
		{
			name:    "Test valid version",
			output:  "10.15.7",
			err:     nil,
			want:    "10.15.7",
			wantErr: false,
		},
		{
			name:    "Test command error",
			output:  "",
			err:     errors.New("command error"),
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := MockCmdRunner{Output: tt.output, Err: tt.err}
			got, err := GetOSVersion(runner)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}
