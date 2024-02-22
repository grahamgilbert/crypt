package utils

import "testing"

func TestStringInSlice(t *testing.T) {
	tests := []struct {
		name string
		str  string
		list []string
		want bool
	}{
		{
			name: "string is in the slice",
			str:  "test",
			list: []string{"one", "two", "test", "three"},
			want: true,
		},
		{
			name: "string is not in the slice",
			str:  "four",
			list: []string{"one", "two", "test", "three"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StringInSlice(tt.str, tt.list); got != tt.want {
				t.Errorf("stringInSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
