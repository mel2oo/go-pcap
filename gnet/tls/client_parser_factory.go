package tls

import (
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

// Returns a parser factory for the client half of a TLS connection.
func NewTLSClientParserFactory() gnet.TCPParserFactory {
	return &tlsClientParserFactory{}
}

type tlsClientParserFactory struct{}

func (*tlsClientParserFactory) Name() string {
	return "TLS 1.2/1.3 Client Parser Factory"
}

func (factory *tlsClientParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}

	return decision, discardFront
}

var clientHelloHandshakeBytes = []byte{
	// Record header (5 bytes)
	0x16,       // handshake record
	0x03, 0x01, // protocol version 3.1 (TLS 1.0)
	0x00, 0x00, // handshake payload size (ignored)

	// Handshake header (4 bytes)
	0x01,             // Client Hello
	0x00, 0x00, 0x00, // Client Hello payload size (ignored)

	// Client Version (2 bytes)
	0x03, 0x03, // protocol version 3.3 (TLS 1.2)
}

var clientHelloHandshakeMask = []byte{
	// Record header (5 bytes)
	0xff,       // handshake record
	0xff, 0xff, // protocol version
	0x00, 0x00, // handshake payload size (ignored)

	// Handshake header (4 bytes)
	0xff,             // Client Hello
	0x00, 0x00, 0x00, // Client Hello payload size (ignored)

	// Client Version (2 bytes)
	0xff, 0xff, // protocol version
}

func (*tlsClientParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < minTLSClientHelloLength_bytes {
		return gnet.NeedMoreData, 0
	}

	// Accept if we match a "Client Hello" handshake message. Reject if we fail to
	// match.
	for idx, expectedByte := range clientHelloHandshakeBytes {
		if input.GetByte(int64(idx))&clientHelloHandshakeMask[idx] != expectedByte {
			return gnet.Reject, input.Len()
		}
	}

	return gnet.Accept, 0
}

func (factory *tlsClientParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newTLSClientHelloParser(id)
}
