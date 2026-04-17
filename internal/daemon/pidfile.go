package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// DefaultPIDFilePath returns ~/.telepath/daemon.pid, the default location
// of the daemon's PID file. Exported for CLI status/stop subcommands.
func DefaultPIDFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/telepath-daemon.pid"
	}
	return filepath.Join(home, ".telepath", "daemon.pid")
}

// ReadPIDFile is the exported form of readPIDFile; CLI uses this to inspect
// daemon status.
func ReadPIDFile(path string) (int, error) { return readPIDFile(path) }

// PIDAlive reports whether a process with the given PID is currently running.
// Exported for CLI status.
func PIDAlive(pid int) bool { return pidAlive(pid) }

// writePIDFile writes pid as a text file at path with 0600 perms, creating
// parent directories as needed.
func writePIDFile(path string, pid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

// readPIDFile parses the PID from path. Non-existent file and unparseable
// contents both return errors.
func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("daemon: invalid pid file %s: %w", path, err)
	}
	return pid, nil
}

// pidAlive reports whether a process with the given PID is currently running.
// Uses signal 0, which performs the permission/existence check without
// actually sending a signal.
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
