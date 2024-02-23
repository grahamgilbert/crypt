package utils

// GetComputerName returns the name of the device
func GetComputerName(runner Runner) (string, error) {
	out, err := runner.Runner.RunCmd("/usr/sbin/scutil", "--get", "ComputerName")
	if err != nil {
		return "", err
	}
	return string(out), nil
}
