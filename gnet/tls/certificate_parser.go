package tls

import (
	"crypto/x509"
	"errors"

	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func newTLSCertificateParser(bidiID uuid.UUID) *tlsCertificateParser {
	return &tlsCertificateParser{
		connectionID: bidiID,
	}
}

type tlsCertificateParser struct {
	connectionID uuid.UUID
	allInput     memview.MemView
}

var _ gnet.TCPParser = (*tlsCertificateParser)(nil)

func (*tlsCertificateParser) Name() string {
	return "TLS Certificate Parser"
}

func (parser *tlsCertificateParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	result, numBytesConsumed, err := parser.parse(input)
	// It's an error if we're at the end and we don't yet have a result.
	if isEnd && result == nil && err == nil {
		// We never got the full TLS record. This is an error.
		err = errors.New("incomplete TLS record for Client Hello")
	}

	totalBytesConsumed = parser.allInput.Len()

	if err != nil {
		return result, memview.MemView{}, totalBytesConsumed, err
	}

	if result != nil {
		unused = parser.allInput.SubView(numBytesConsumed, parser.allInput.Len())
		totalBytesConsumed -= unused.Len()
		return result, unused, totalBytesConsumed, nil
	}

	return nil, memview.MemView{}, totalBytesConsumed, nil
}

func (parser *tlsCertificateParser) parse(input memview.MemView) (result gnet.ParsedNetworkContent, numBytesConsumed int64, err error) {
	// Add the incoming bytes to our buffer.
	parser.allInput.Append(input)

	// handshake(1)
	// 	version(2)
	// 	length(2)
	// Handshake Type: Certificate(11) (1)
	// 	Length (3)
	// 	Certificates Length(3)
	if parser.allInput.Len() < 12 {
		return nil, 0, nil
	}
	// The last two bytes of the record header give the total length of the
	// handshake message that appears after the record header.
	handshakeMsgLen_bytes := parser.allInput.GetUint16(tlsRecordHeaderLength_bytes - 2)
	handshakeMsgEndPos := int64(tlsRecordHeaderLength_bytes + handshakeMsgLen_bytes)
	// Wait until we have the full handshake record.
	if parser.allInput.Len() < handshakeMsgEndPos {
		return nil, 0, nil
	}
	// Get a Memview of the handshake record and a corresponding reader.
	// buf -> Handshake Certificate
	buf := parser.allInput.SubView(tlsRecordHeaderLength_bytes, handshakeMsgEndPos)
	var offset int64 = 1 + 3
	certLen := buf.GetUint24(offset)
	offset += 3
	// buf -> Certificates
	buf = buf.SubView(offset, int64(certLen)+offset)
	cert := gnet.TLSCertificate{
		ConnectionID: parser.connectionID,
		Certificates: make([]*x509.Certificate, 0),
	}
	// frist certificates
	certLen = buf.GetUint24(0)
	offset = 3
	buf1 := buf.SubView(offset, int64(certLen)+offset)
	c, err := x509.ParseCertificate(buf1.Bytes())
	if err != nil {
		return nil, handshakeMsgEndPos, err
	}
	cert.Certificates = append(cert.Certificates, c)
	// second certificates
	offset += int64(certLen)
	certLen = buf.GetUint24(offset)
	offset += 3
	buf1 = buf.SubView(offset, int64(certLen)+offset)
	c, err = x509.ParseCertificate(buf1.Bytes())
	if err != nil {
		return nil, handshakeMsgEndPos, err
	}
	cert.Certificates = append(cert.Certificates, c)

	return cert, handshakeMsgEndPos, nil
}
