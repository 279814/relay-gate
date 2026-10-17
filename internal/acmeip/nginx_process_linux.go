//go:build linux

package acmeip

import (
	"os/exec"
	"syscall"
)

func configureNginxProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killNginxProcess(command *exec.Cmd) error {
	// Killing only the master can leave workers holding business listeners.
	// The group contains this manager's Nginx master and its worker descendants.
	return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}
