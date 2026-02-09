package whitewolf

import (
	"context"
	"net"

	"github.com/xtls/reality"
)

// Server runs a TLS handshake as the destination (e.g. Google) and accepts every client.
// It uses the same machinery as Reality but with AcceptAll, so the connection is always
// passed to the proxy handler.
func Server(c net.Conn, config *reality.Config) (net.Conn, error) {
	return reality.Server(context.Background(), c, config)
}
