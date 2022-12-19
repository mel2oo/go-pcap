package tls

import (
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func newTLSClientHelloParser(bidiID uuid.UUID) *tlsClientHelloParser {
	return &tlsClientHelloParser{
		connectionID: bidiID,
	}
}

type tlsClientHelloParser struct {
	connectionID uuid.UUID
	allInput     memview.MemView
}

var _ gnet.TCPParser = (*tlsClientHelloParser)(nil)

func (*tlsClientHelloParser) Name() string {
	return "TLS 1.2/1.3 Client-Hello Parser"
}

func (parser *tlsClientHelloParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
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

func (parser *tlsClientHelloParser) parse(input memview.MemView) (result gnet.ParsedNetworkContent, numBytesConsumed int64, err error) {
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

	// Get a Memview of the handshake record and a corresponding reader.
	buf := parser.allInput.SubView(tlsRecordHeaderLength_bytes, handshakeMsgEndPos)
	reader := buf.CreateReader()

	// Seek past some headers.
	_, err = reader.Seek(handshakeHeaderLength_bytes+clientVersionLength_bytes+clientRandomLength_bytes, io.SeekCurrent)
	if err != nil {
		return nil, 0, err
	}

	// Now at the session ID, which is a variable-length vector. Seek past this.
	// The first byte indicates the vector's length in bytes.
	err = reader.ReadByteAndSeek()
	if err != nil {
		return nil, 0, err
	}

	// Now at the cipher suites. Seek past this. The first two bytes gives the
	// length of this header in bytes.
	err = reader.ReadUint16AndSeek()
	if err != nil {
		return nil, 0, err
	}

	// Now at the compression methods. Seek past this. The first byte gives the
	// length of this header in bytes.
	err = reader.ReadByteAndSeek()
	if err != nil {
		return nil, 0, err
	}

	// Now at the extensions. Isolate this section in the reader. The first two
	// bytes gives the length of the extensions in bytes.
	_, reader, err = reader.ReadUint16AndTruncate()
	if err != nil {
		return nil, 0, errors.New("malformed TLS message")
	}

	dnsHostname := (*string)(nil)
	protocols := []string{}

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

		// Seek the main reader past the extension.
		_, err = reader.Seek(int64(extensionContentLength_bytes), io.SeekCurrent)
		if err != nil {
			return nil, 0, err
		}

		switch extensionType {
		case serverNameTLSExtensionID:
			serverName, err := parser.parseServerNameExtension(extensionReader)
			if err == nil {
				dnsHostname = &serverName
			}

		case alpnTLSExtensionID:
			protocols = parser.parseALPNExtension(extensionReader)
		}
	}

	hello := gnet.TLSClientHello{
		ConnectionID:       parser.connectionID,
		Hostname:           dnsHostname,
		SupportedProtocols: protocols,
	}

	return hello, handshakeMsgEndPos, nil
}

// Extracts the DNS hostname from a buffer containing a TLS SNI extension.
func (*tlsClientHelloParser) parseServerNameExtension(reader *memview.MemViewReader) (hostname string, err error) {
	// The SNI extension is a list of server names, each of a different type.
	// Currently, the only supported type is DNS (type 0x00) according to RFC
	// 6066.
	for {
		// First two bytes gives the length of the list entry. Isolate the entry in
		// its own reader.
		entryLen_bytes, entryReader, err := reader.ReadUint16AndTruncate()
		if err == io.EOF {
			// Out of entries.
			break
		} else if err != nil {
			return "", err
		}

		// Seek past the entry in the main reader.
		_, err = reader.Seek(int64(entryLen_bytes), io.SeekCurrent)
		if err != nil {
			return "", err
		}

		// First byte in the entry is the entry type.
		var entryType sniType
		{
			val, err := entryReader.ReadByte()
			if err != nil {
				return "", err
			}
			entryType = sniType(val)
		}

		switch entryType {
		case dnsHostnameSNIType:
			// The next two bytes gives the length of the hostname in bytes.
			hostname, err := entryReader.ReadString_uint16()
			if err != nil {
				return "", errors.New("malformed SNI extension entry")
			}
			return hostname, nil
		}
	}

	return "", errors.New("no DNS hostname found in SNI extension")
}

// Extracts the list of protocols from a buffer containing a TLS ALPN extension.
func (*tlsClientHelloParser) parseALPNExtension(reader *memview.MemViewReader) []string {
	result := []string{}
	var err error

	// The ALPN extension is a list of strings indicating the protocols supported
	// by the client. Isolate this list in the reader. The first two bytes gives
	// the length of the list in bytes.
	_, reader, err = reader.ReadUint16AndTruncate()
	if err != nil {
		return result
	}

	for {
		// The first byte of each list element gives the length of the string in
		// bytes.
		protocol, err := reader.ReadString_byte()
		if err != nil {
			// Out of elements.
			return result
		}

		result = append(result, string(protocol))
	}
}
