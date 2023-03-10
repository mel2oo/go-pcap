package tls

import (
	"io"

	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
	"github.com/pkg/errors"
)

func newTLSServerHelloParser(bidiID uuid.UUID) *tlsServerHelloParser {
	return &tlsServerHelloParser{
		connectionID: bidiID,
	}
}

type tlsServerHelloParser struct {
	connectionID uuid.UUID
	allInput     memview.MemView
}

var _ gnet.TCPParser = (*tlsServerHelloParser)(nil)

func (*tlsServerHelloParser) Name() string {
	return "TLS Server-Hello Parser"
}

func (parser *tlsServerHelloParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	result, numBytesConsumed, err := parser.parse(input)
	// It's an error if we're at the end and we don't yet have a result.
	if isEnd && result == nil && err == nil {
		// We never got the full TLS record. This is an error.
		err = errors.New("incomplete TLS record for Server Hello")
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

func (parser *tlsServerHelloParser) parse(input memview.MemView) (result gnet.ParsedNetworkContent, numBytesConsumed int64, err error) {
	// Add the incoming bytes to our buffer.
	parser.allInput.Append(input)

	// Wait until we have at least the TLS record header.
	if parser.allInput.Len() < tlsRecordHeaderLength_bytes {
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

	// Get a Memview of the handshake record.
	buf := parser.allInput.SubView(tlsRecordHeaderLength_bytes, handshakeMsgEndPos)
	reader := buf.CreateReader()

	hello := gnet.TLSServerHello{
		ConnectionID: parser.connectionID,
	}
	// seak handshake header
	_, err = reader.Seek(handshakeHeaderLength_bytes, io.SeekCurrent)
	if err != nil {
		return nil, 0, err
	}

	// read version
	v, err := reader.ReadUint16()
	if err != nil {
		return nil, 0, err
	}
	hello.Version = gnet.TLSVersion(v)

	// seek random
	_, err = reader.Seek(clientRandomLength_bytes, io.SeekCurrent)
	if err != nil {
		return nil, 0, err
	}

	// seek session
	err = reader.ReadByteAndSeek()
	if err != nil {
		return nil, 0, err
	}

	// read cipher suite
	hello.CipherSuite, err = reader.ReadUint16()
	if err != nil {
		return nil, 0, err
	}

	// seek (1) compression method
	_, err = reader.Seek(serverCompressionMethodLength_bytes, io.SeekCurrent)
	if err != nil {
		return nil, 0, err
	}

	// Now at the extensions. Isolate this section in the reader. The first two
	// bytes gives the length of the extensions in bytes.
	_, reader, err = reader.ReadUint16AndTruncate()
	if err != nil {
		return nil, 0, errors.New("malformed TLS message")
	}

	for {
		// The first two bytes of the extension give the extension type.
		var extensionType tlsExtensionID
		{
			val, err := reader.ReadUint16()
			if err == io.EOF {
				// Out of extensions.
				break
			} else if err != nil {
				return nil, 0, err
			}
			extensionType = tlsExtensionID(val)
		}
		// append extensions
		hello.Extensions = append(hello.Extensions, uint16(extensionType))
		// seek extension
		reader.ReadUint16AndSeek()
		if err != nil {
			return nil, 0, err
		}
	}

	return hello, handshakeMsgEndPos, nil
}
