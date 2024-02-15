package utils

import (
	"os/exec"
	"strings"
)

type CmdRunner interface {
	RunCmd(name string, arg ...string) ([]byte, error)
}

type RealCmdRunner struct{}

func (r RealCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	return exec.Command(name, arg...).Output()
}

func GetOSVersion(runner CmdRunner) (string, error) {
	out, err := runner.RunCmd("/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
