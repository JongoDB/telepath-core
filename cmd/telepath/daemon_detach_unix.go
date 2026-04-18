//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// applyDetachedSysProcAttr puts the child daemon in its own session so it
// survives the parent shell closing. Unix-only; Windows gets a stub.
func applyDetachedSysProcAttr(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
}
