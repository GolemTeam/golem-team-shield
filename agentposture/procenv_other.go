//go:build !darwin

package agentposture

type osProcesses struct{}

func (osProcesses) Alive(int) bool { return false }

func (osProcesses) Environ(int) ([]string, bool) { return nil, false }

func ProcessEnviron(int) ([]string, bool) { return nil, false }
