//go:build !darwin
// +build !darwin

package utils

func Pref(prefName string) (interface{}, error) {
	return nil, nil
}
