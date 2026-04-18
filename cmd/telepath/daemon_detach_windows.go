//go:build windows

package main

import "os/exec"

// applyDetachedSysProcAttr is a no-op on Windows; --detach returns an
// error in daemon_cmd.go before this is reached, so operators are told
// the mode isn't supported. A proper Windows implementation needs
// CreateProcess with DETACHED_PROCESS via golang.org/x/sys/windows,
// planned for a later release.
func applyDetachedSysProcAttr(cmd *exec.Cmd) {}
