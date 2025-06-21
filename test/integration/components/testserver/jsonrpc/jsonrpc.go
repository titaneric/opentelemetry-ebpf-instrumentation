package jsonrpc

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
)

// Args defines the arguments for the RPC methods.
type Args struct {
	A, B int
}

// Arith provides methods for arithmetic operations.
type Arith struct{}

// Multiply multiplies two numbers and returns the result.
func (t *Arith) Multiply(args *Args, reply *int) error {
	*reply = args.A * args.B
	return nil
}

// ReadWriteCloserWrapper wraps an io.Reader and io.Writer to implement io.ReadWriteCloser.
type ReadWriteCloserWrapper struct {
	io.Reader
	io.Writer
}

// Close is a no-op to satisfy the io.ReadWriteCloser interface.
func (w *ReadWriteCloserWrapper) Close() error {
	return nil
}

func Setup(port int) {
	arith := new(Arith)
	rpc.Register(arith)

	log := slog.With("component", "jsonrpc.Server")
	address := fmt.Sprintf(":%d", port)
	log.Info("starting JSON-RPC server", "address", address)
	err := http.ListenAndServe(address, HTTPHandler(log, port))
	log.Error("JSON-RPC server has unexpectedly stopped", "error", err)
}

func HTTPHandler(log *slog.Logger, echoPort int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)
		if req.RequestURI == "/jsonrpc" {
			if req.Method != http.MethodPost {
				http.Error(rw, "Only POST method is allowed", http.StatusMethodNotAllowed)
				return
			}
			// Wrap the request body and response writer in a ReadWriteCloser.
			conn := &ReadWriteCloserWrapper{Reader: req.Body, Writer: rw}
			// Serve the request using JSON-RPC codec.
			rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
		} else {
			http.NotFound(rw, req)
		}
	}
}
