package utils

type MockCmdRunner struct {
	Output string
	Err    error
}

func (m MockCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	return []byte(m.Output), m.Err
}

func (m MockCmdRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	return []byte(m.Output), m.Err
}
