package ipc

import "net"

// dialUnix is a tiny test helper: raw Unix-socket dial without wrapping in a
// JSON-RPC client.
func dialUnix(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}
