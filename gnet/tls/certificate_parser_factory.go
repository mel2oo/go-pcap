package tls

import (
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func NewTLSCertificateParserFactory() gnet.TCPParserFactory {
	return &tlsCertificateParserFactory{}
}

type tlsCertificateParserFactory struct{}

func (*tlsCertificateParserFactory) Name() string {
	return "TLS Certificate Parser Factory"
}

func (factory *tlsCertificateParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}

	return decision, discardFront
}

var tlsHandshakeCertificateBytes = []byte{
	// Record header (5 bytes)
	0x16,       // handshake record
	0x03, 0x00, // protocol version 3.x (TLS 1.0)
	0x00, 0x00, // handshake payload size (ignored)

	// Handshake header (4 bytes)
	0x0b,             // Certificate
	0x00, 0x00, 0x00, // Certificate payload size (ignored)
}

var tlsHandshakeCertificateMask = []byte{
	// Record header (5 bytes)
	0xff,       // handshake record
	0xff, 0x00, // protocol version
	0x00, 0x00, // handshake payload size (ignored)

	// Handshake header (4 bytes)
	0xff,             // Certificate
	0x00, 0x00, 0x00, // Certificate payload size (ignored)
}

func (*tlsCertificateParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < minTLSClientHelloLength_bytes {
		return gnet.NeedMoreData, 0
	}

	// Accept if we match a "Certificate" handshake message. Reject if we fail to
	// match.
	for idx, expectedByte := range tlsHandshakeCertificateBytes {
		if input.GetByte(int64(idx))&tlsHandshakeCertificateMask[idx] != expectedByte {
			return gnet.Reject, input.Len()
		}
	}

	return gnet.Accept, 0
}

func (factory *tlsCertificateParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newTLSCertificateParser(id)
}
