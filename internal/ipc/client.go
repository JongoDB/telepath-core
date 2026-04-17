package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/fsc/telepath-core/pkg/schema"
)

// DefaultTimeout bounds how long Call will wait for a full round-trip before
// giving up. Individual callers can override via CallWithTimeout.
const DefaultTimeout = 10 * time.Second

// Call opens a connection to the daemon at path, sends a single JSON-RPC
// request, reads one response, and closes the connection. Returns the
// response's Result payload on success or a descriptive error otherwise.
func Call(path, method string, params any) (json.RawMessage, error) {
	return CallWithTimeout(path, method, params, DefaultTimeout)
}

// CallWithTimeout is Call with an explicit timeout.
func CallWithTimeout(path, method string, params any, timeout time.Duration) (json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial %s: %w", path, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var rawParams json.RawMessage
	if params != nil {
		pbytes, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("ipc: marshal params: %w", err)
		}
		rawParams = pbytes
	}
	req := schema.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  rawParams,
		ID:      1,
	}
	reqBytes, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("ipc: marshal request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("ipc: write: %w", err)
	}

	var resp schema.JSONRPCResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("ipc: read response: %w", err)
	}
	if resp.Error != nil {
		return nil, &RemoteError{Code: resp.Error.Code, Message: resp.Error.Message}
	}
	return resp.Result, nil
}

// RemoteError is returned by Call when the daemon responds with a structured
// error. Callers can errors.As to extract the code for custom behavior.
type RemoteError struct {
	Code    int
	Message string
}

// Error implements error.
func (e *RemoteError) Error() string {
	return fmt.Sprintf("telepath daemon error %d: %s", e.Code, e.Message)
}
