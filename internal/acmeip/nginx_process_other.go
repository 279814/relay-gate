//go:build !linux

package acmeip

import "os/exec"

func configureNginxProcess(*exec.Cmd)          {}
func killNginxProcess(command *exec.Cmd) error { return command.Process.Kill() }
