package utils

import (
	"bytes"
	"errors"
	"os/exec"
)

type CmdRunner interface {
	RunCmd(name string, arg ...string) ([]byte, error)
	RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error)
}

type ExecCmdRunner struct{}

type Runner struct {
	Runner CmdRunner
}

// New creates a new Runner struct
func NewRunner() Runner {
	return Runner{
		Runner: &ExecCmdRunner{},
	}
}

func (r ExecCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return output, errors.New(stderr.String())
	}
	return output, nil
}

func (r *ExecCmdRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = bytes.NewBuffer([]byte(stdin))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		return output, errors.New(stderr.String())
	}
	return output, nil
}
