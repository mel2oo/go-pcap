package tls

const (
	// Minimum number of bytes needed before we can determine whether we can
	// accept some bytes as a TLS 1.2 or 1.3 Client Hello.
	//
	// We read through to the client version, to have better assurance that we
	// don't accidentally match against something else.
	//
	//   Record header (5 bytes)
	//     16 - handshake record
	//     03 01 - protocol version 3.1 (TLS 1.0)
	//     XX XX - bytes of handshake message follows
	//
	//   Handshake header (4 bytes)
	//     01 - Client Hello
	//     XX XX XX - bytes of Client Hello follows
	//
	//   Client Version (2 bytes)
	//     03 03 - protocol version 3.3 (TLS 1.2)
	minTLSClientHelloLength_bytes = 11

	// Minimum number of bytes needed before we can determine whether we can
	// accept some bytes as a TLS 1.2 or 1.3 Server Hello.
	//
	// We read through to the server version, to have better assurance that we
	// don't accidentally match against something else.
	//
	//   Record header (5 bytes)
	//     16 - handshake record
	//     03 03 - protocol version 3.3 (TLS 1.2)
	//     XX XX - bytes of handshake message follows
	//
	//   Handshake header (4 bytes)
	//     02 - Server Hello
	//     XX XX XX - bytes of Client Hello follows
	//
	//   Server Version (2 bytes)
	//     03 03 - protocol version 3.3 (TLS 1.2)
	minTLSServerHelloLength_bytes = 11

	// handshake(1) + version(2) + length(2)
	tlsRecordHeaderLength_bytes = 5

	// handshake(1) + length(3)
	handshakeHeaderLength_bytes = 4
	clientVersionLength_bytes   = 2
	clientRandomLength_bytes    = 32

	serverVersionLength_bytes           = 2
	serverRandomLength_bytes            = 32
	serverCiphersuiteLength_bytes       = 2
	serverCompressionMethodLength_bytes = 1
)

type tlsExtensionID uint16

// TLS extension numbers
const (
	serverNameExtensionID           tlsExtensionID = 0
	supportedCurvesExtensionID      tlsExtensionID = 10
	supportedPointsExtensionID      tlsExtensionID = 11
	alpnExtensionID                 tlsExtensionID = 16
	supportedVersionsTLSExtensionID tlsExtensionID = 0x00_2b
)

type sniType byte

const (
	dnsHostnameSNIType sniType = 0x00
)
