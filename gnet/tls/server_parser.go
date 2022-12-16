package tls

import (
	"crypto/x509"
	"io"

	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
	"github.com/pkg/errors"
)

func newTLSServerHelloParser(bidiID gnet.TCPBidiID) *tlsServerHelloParser {
	return &tlsServerHelloParser{
		connectionID: gid.NewConnectionID(uuid.UUID(bidiID)),
	}
}

type tlsServerHelloParser struct {
	connectionID gid.ConnectionID
	allInput     memview.MemView
}

var _ gnet.TCPParser = (*tlsServerHelloParser)(nil)

func (*tlsServerHelloParser) Name() string {
	return "TLS 1.2/1.3 Server-Hello Parser"
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

	// Seek past some headers.
	_, err = reader.Seek(handshakeHeaderLength_bytes+serverVersionLength_bytes+serverRandomLength_bytes, io.SeekCurrent)
	if err != nil {
		return nil, 0, err
	}

	// Now at the session ID, which is a variable-length vector. Seek past this.
	// The first byte indicates the vector's length in bytes.
	err = reader.ReadByteAndSeek()
	if err != nil {
		return nil, 0, err
	}

	// Seek past more headers.
	_, err = reader.Seek(serverCiphersuiteLength_bytes+serverCompressionMethodLength_bytes, io.SeekCurrent)
	if err != nil {
		return nil, 0, err
	}

	// Now at the extensions. Isolate this section in the reader. The first two
	// bytes gives the length of the extensions in bytes.
	_, reader, err = reader.ReadUint16AndTruncate()
	if err != nil {
		return nil, 0, errors.New("malformed TLS message")
	}

	selectedVersion := gnet.TLS_v1_2
	selectedProtocol := (*string)(nil)
	dnsNames := ([]string)(nil)

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

		// The following two bytes give the extension's content length in bytes.
		// Isolate the extension in its own reader.
		extensionContentLength_bytes, extensionReader, err := reader.ReadUint16AndTruncate()
		if err != nil {
			return nil, 0, err
		}

		// Seek past the extension in the main reader.
		_, err = reader.Seek(int64(extensionContentLength_bytes), io.SeekCurrent)
		if err != nil {
			return nil, 0, err
		}

		switch extensionType {
		case supportedVersionsTLSExtensionID:
			version, err := parser.parseSupportedVersionsExtension(extensionReader)
			if err == nil {
				selectedVersion = version
			}

		case alpnTLSExtensionID:
			protocol, err := parser.parseALPNExtension(extensionReader)
			if err == nil {
				selectedProtocol = &protocol
			}
		}
	}

	if selectedVersion == gnet.TLS_v1_2 {
		// We have TLS 1.2. There should be a second TLS record with a handshake
		// message containing the server's certificate. Get the certificate's CN and
		// SANs.

		// Get a view of the bytes after the first handshake message.
		buf := parser.allInput.SubView(handshakeMsgEndPos, parser.allInput.Len())

		// Wait until we have at least the header for the second TLS record.
		if buf.Len() < tlsRecordHeaderLength_bytes {
			return nil, 0, nil
		}

		// Expect the first three bytes to be as follows:
		//   0x16 - handshake record
		//   0x0303 - protocol version 3.3 (TLS 1.2)
		for idx, expectedByte := range []byte{0x16, 0x03, 0x03} {
			if buf.GetByte(int64(idx)) != expectedByte {
				return nil, 0, errors.New("expected a TLS message containing the server's certificate, but found a malformed TLS record")
			}
		}

		// The last two bytes of the record header give the total length of the
		// handshake message that appears after the record header.
		handshakeMsgLen_bytes := buf.GetUint16(tlsRecordHeaderLength_bytes - 2)
		handshakeMsgEndPos = int64(tlsRecordHeaderLength_bytes + handshakeMsgLen_bytes)

		// Wait until we have the full handshake record.
		if buf.Len() < handshakeMsgEndPos {
			return nil, 0, nil
		}

		// Get a Memview of the handshake record.
		buf = buf.SubView(tlsRecordHeaderLength_bytes, handshakeMsgEndPos)
		reader := buf.CreateReader()

		// The first byte of the handshake message gives its type. Expect a
		// certificate handshake message (type 0x0b).
		messageType, err := reader.ReadByte()
		if err != nil {
			return nil, 0, errors.New("expected a TLS message containing the server's certificate, but found a malformed handshake message")
		}
		if messageType != 0x0b {
			return nil, 0, errors.Errorf("expected a TLS certificate handshake message (type 13) containing the server's certificate, but found a type %d handshake message", messageType)
		}

		// The next three bytes gives the length of the certificate message. Isolate
		// the certificate message in the reader.
		_, reader, err = reader.ReadUint24AndTruncate()
		if err != nil {
			return nil, 0, errors.New("expected a TLS message containing the server's certificate, but found a malformed certificate handshake message")
		}

		// The next three bytes gives the length of the certificate data that
		// follows. Isolate the certificate data in the reader.
		_, reader, err = reader.ReadUint24AndTruncate()
		if err != nil {
			return nil, 0, errors.New("expected a TLS message containing the server's certificate, but found a malformed certificate handshake message")
		}

		// The first certificate is the one that was issued to the server, so we
		// only need to look at that.

		// The next three bytes gives the length of the first certificate.
		var certLen_bytes int64
		{
			val, err := reader.ReadUint24()
			if err != nil {
				return nil, 0, errors.New("expected a TLS message containing the server's certificate, but found a malformed certificate handshake message")
			}
			certLen_bytes = int64(val)
		}

		// Extract the first certificate.
		certBytes := make([]byte, certLen_bytes)
		read, err := reader.Read(certBytes)
		if read != int(certLen_bytes) || err != nil {
			return nil, 0, errors.New("expected a TLS message containing the server's certificate, but found a malformed certificate handshake message")
		}

		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, 0, errors.Wrap(err, "error parsing server certificate")
		}

		dnsNames = cert.DNSNames
	}

	hello := gnet.TLSServerHello{
		ConnectionID:     parser.connectionID,
		Version:          selectedVersion,
		SelectedProtocol: selectedProtocol,
		DNSNames:         dnsNames,
	}

	return hello, handshakeMsgEndPos, nil
}

// Extracts the server-selected TLS version from a buffer containing a TLS
// Supported Versions extension.
func (*tlsServerHelloParser) parseSupportedVersionsExtension(reader *memview.MemViewReader) (selectedVersion gnet.TLSVersion, err error) {
	selected, err := reader.ReadUint16()
	if err != nil {
		return "", errors.New("malformed Supported Versions extension")
	}

	if result, exists := tlsVersionMap[selected]; exists {
		return result, nil
	}

	return "", errors.Errorf("unknown TLS version selected: %d", selected)
}

// Extracts the server-selected application-layer protocol from a buffer
// containing a TLS ALPN extension.
func (*tlsServerHelloParser) parseALPNExtension(reader *memview.MemViewReader) (string, error) {
	// The first two bytes give the length of the rest of the ALPN extension.
	// Isolate the rest of the extension in the reader.
	_, reader, err := reader.ReadUint16AndTruncate()
	if err != nil {
		return "", errors.New("malformed ALPN extension")
	}

	// The next byte gives the length of the string indicating the selected
	// protocol.
	alpn, err := reader.ReadString_byte()
	if err != nil {
		return "", errors.New("malformed ALPN extension")
	}
	return alpn, nil
}
