//go:build !darwin
// +build !darwin

package utils

func GetConsoleUser() (string, error) {
	return "UNKNOWN", nil
}
