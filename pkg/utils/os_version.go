package utils

import (
	"strings"
)

func GetOSVersion(runner CmdRunner) (string, error) {
	out, err := runner.RunCmd("/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
