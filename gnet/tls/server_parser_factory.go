package tls

import (
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

// Returns a parser factory for the server half of a TLS connection.
func NewTLSServerParserFactory() gnet.TCPParserFactory {
	return &tlsServerParserFactory{}
}

type tlsServerParserFactory struct{}

func (*tlsServerParserFactory) Name() string {
	return "TLS Server Parser Factory"
}

func (factory *tlsServerParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}

	return decision, discardFront
}

var serverHelloHandshakeBytes = []byte{
	// Record header (5 bytes)
	0x16,       // handshake record
	0x03, 0x00, // protocol version 3.x (TLS 1.2)
	0x00, 0x00, // handshake payload size (ignored)

	// Handshake header (4 bytes)
	0x02,             // Server Hello
	0x00, 0x00, 0x00, // Server Hello payload size (ignored)

	// Server Version (2 bytes)
	0x03, 0x00, // protocol version 3.x (TLS 1.0)
}

var serverHelloHandshakeMask = []byte{
	// Record header (5 bytes)
	0xff,       // handshake record
	0xff, 0x00, // protocol version
	0x00, 0x00, // handshake payload size (ignored)

	// Handshake header (4 bytes)
	0xff,             // Server Hello
	0x00, 0x00, 0x00, // Server Hello payload size (ignored)

	// Server Version (2 bytes)
	0xff, 0x00, // protocol version
}

func (*tlsServerParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < minTLSServerHelloLength_bytes {
		return gnet.NeedMoreData, 0
	}

	// Accept if we match a "Server Hello" handshake message. Reject if we fail to
	// match.
	for idx, expectedByte := range serverHelloHandshakeBytes {
		if input.GetByte(int64(idx))&serverHelloHandshakeMask[idx] != expectedByte {
			return gnet.Reject, input.Len()
		}
	}

	return gnet.Accept, 0
}

func (factory *tlsServerParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newTLSServerHelloParser(id)
}
