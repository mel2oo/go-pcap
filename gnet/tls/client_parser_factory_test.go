package tls

import "testing"

// Ensures that bits set in clientHelloHandshakeBytes are also set in
// clientHelloHandshakeMask.
func TestClientHelloHandshakeMask(t *testing.T) {
	if len(clientHelloHandshakeBytes) != len(clientHelloHandshakeMask) {
		t.Errorf("clientHelloHandshakeBytes has length %d but clientHelloHandshakeMask has length %d", len(clientHelloHandshakeBytes), len(clientHelloHandshakeMask))
	}

	for i := range clientHelloHandshakeBytes {
		b := clientHelloHandshakeBytes[i]
		mask := clientHelloHandshakeMask[i]
		if b&mask != b {
			t.Errorf("Bits set in clientHelloHandshakeBytes[%d] are being masked", i)
		}
	}
}
