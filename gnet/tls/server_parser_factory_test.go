package tls

import "testing"

// Ensures that bits set in serverHelloHandshakeBytes are also set in
// serverHelloHandshakeMask.
func TestServerHelloHandshakeMask(t *testing.T) {
	if len(serverHelloHandshakeBytes) != len(serverHelloHandshakeMask) {
		t.Errorf("serverHelloHandshakeBytes has length %d but serverHelloHandshakeMask has length %d", len(serverHelloHandshakeBytes), len(serverHelloHandshakeMask))
	}

	for i := range serverHelloHandshakeBytes {
		b := serverHelloHandshakeBytes[i]
		mask := serverHelloHandshakeMask[i]
		if b&mask != b {
			t.Errorf("Bits set in serverHelloHandshakeBytes[%d] are being masked", i)
		}
	}
}
