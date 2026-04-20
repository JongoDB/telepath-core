package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/fsc/telepath-core/internal/ipc"
)

// socketPath returns the path the CLI will use to reach the daemon. It honors
// TELEPATH_SOCKET for tests; otherwise it defaults to ipc.DefaultSocketPath
// (/tmp/telepath-<uid>.sock), which also matches the Python hook library.
func socketPath() string {
	if s := os.Getenv("TELEPATH_SOCKET"); s != "" {
		return s
	}
	return ipc.DefaultSocketPath()
}

// rpc makes a JSON-RPC call to the daemon and, if dst is non-nil, unmarshals
// the result into it. Errors from the daemon are surfaced with their
// original message; transport errors are wrapped with an actionable hint.
func rpc(method string, params any, dst any) error {
	sock := socketPath()
	res, err := ipc.Call(sock, method, params)
	if err != nil {
		var re *ipc.RemoteError
		if errors.As(err, &re) {
			return errors.New(re.Message)
		}
		return fmt.Errorf("telepath daemon unreachable at %s: %v\n(start it with `telepath start` — or `telepath daemon run` for granular control)", sock, err)
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(res, dst)
}
