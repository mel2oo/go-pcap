package gnet

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/mel2oo/go-pcap/mempool"
	"github.com/mel2oo/go-pcap/memview"
)

// Represents a generic network traffic that has been parsed from the wire.
type NetTraffic struct {
	LayerType string
	SrcIP     net.IP
	SrcPort   int
	DstIP     net.IP
	DstPort   int

	// origin data
	Payload []byte

	// parse data
	Content ParsedNetworkContent

	// stream id
	ConnectionID uuid.UUID

	// The time at which the first packet was observed
	ObservationTime time.Time

	// The time at which the final packet arrived, for
	// multi-packet content.  Equal to ObservationTime
	// for single packets.
	FinalPacketTime time.Time
}

// Interface implemented by all types of data that can be parsed from the
// network.
type ParsedNetworkContent interface {
	ReleaseBuffers()
}

// Content bytes length.
type DroppedBytes int64

var _ ParsedNetworkContent = (*DroppedBytes)(nil)

func (DroppedBytes) ReleaseBuffers() {}

// Represents metadata from an observed TCP packet.
type TCPPacketMetadata struct {
	// Whether the SYN flag was set in the observed packet.
	SYN bool

	// Whether the ACK flag was set in the observed packet.
	ACK bool

	// Whether the FIN flag was set in the observed packet.
	FIN bool

	// Whstring   {}ether the RST flag was set in the observed packet.
	RST bool
}

var _ ParsedNetworkContent = (*TCPPacketMetadata)(nil)

func (TCPPacketMetadata) ReleaseBuffers() {}

// Represents metadata from an observed TCP connection.
type TCPConnectionMetadata struct {
	// Uniquely identifies a TCP connection.
	ConnectionID uuid.UUID

	// Identifies which side of the connection was the connection initiator.
	Initiator TCPConnectionInitiator

	// Whether and how the connection was closed.
	EndState TCPConnectionEndState
}

var _ ParsedNetworkContent = (*TCPConnectionMetadata)(nil)

func (TCPConnectionMetadata) ReleaseBuffers() {}

// Identifies which of the two endpoints of a connection initiated that
// connection.
type TCPConnectionInitiator int

const (
	UnknownTCPConnectionInitiator TCPConnectionInitiator = iota

	// Indicates that the "source" endpoint initiated the connection.
	SourceInitiator

	// Indicates that the "destination" endpoint initiated the connection.
	DestInitiator
)

// Indicates whether a TCP connection was closed, and if so, how.
type TCPConnectionEndState string

const (
	// Neither the FIN nor RST flag was seen.
	ConnectionOpen TCPConnectionEndState = "OPEN"

	// The FIN flag was seen, but not the RST flag.
	ConnectionClosed TCPConnectionEndState = "CLOSED"

	// The RST flag was seen.
	ConnectionReset TCPConnectionEndState = "RESET"
)

type DNSRequest struct {
	// Header fields
	ID     uint16
	QR     bool
	OpCode layers.DNSOpCode

	AA bool  // Authoritative answer
	TC bool  // Truncated
	RD bool  // Recursion desired
	RA bool  // Recursion available
	Z  uint8 // Reserved for future use

	ResponseCode layers.DNSResponseCode
	QDCount      uint16 // Number of questions to expect
	ANCount      uint16 // Number of answers to expect
	NSCount      uint16 // Number of authorities to expect
	ARCount      uint16 // Number of additional records to expect

	// Entries
	Questions   []layers.DNSQuestion
	Answers     []layers.DNSResourceRecord
	Authorities []layers.DNSResourceRecord
	Additionals []layers.DNSResourceRecord
}

var _ ParsedNetworkContent = (*DNSRequest)(nil)

func (DNSRequest) ReleaseBuffers() {}

type HTTPRequest struct {
	// StreamID and Seq uniquely identify a pair of request and response.
	StreamID uuid.UUID
	Seq      int

	Method           string
	ProtoMajor       int // e.g. 1 in HTTP/1.0
	ProtoMinor       int // e.g. 0 in HTTP/1.0
	URL              *url.URL
	Host             string
	Header           http.Header
	Body             memview.MemView
	BodyDecompressed bool // true if the body is already decompressed
	Cookies          []*http.Cookie

	// The buffer (if any) that owns the storage backing the request body.
	buffer mempool.Buffer
}

var _ ParsedNetworkContent = (*HTTPRequest)(nil)

func (r HTTPRequest) ReleaseBuffers() { r.buffer.Release() }

// Returns a string key that associates this request with its corresponding
// response.
func (r HTTPRequest) GetStreamKey() string {
	return r.StreamID.String() + ":" + strconv.Itoa(r.Seq)
}

type HTTPResponse struct {
	// StreamID and Seq uniquely identify a pair of request and response.
	StreamID uuid.UUID
	Seq      int

	StatusCode       int
	ProtoMajor       int // e.g. 1 in HTTP/1.0
	ProtoMinor       int // e.g. 0 in HTTP/1.0
	Header           http.Header
	Body             memview.MemView
	BodyDecompressed bool // true if the body is already decompressed
	Cookies          []*http.Cookie

	// The buffer (if any) that owns the storage backing the request body.
	buffer mempool.Buffer
}

var _ ParsedNetworkContent = (*HTTPResponse)(nil)

func (r HTTPResponse) ReleaseBuffers() { r.buffer.Release() }

// Returns a string key that associates this response with its corresponding
// request.
func (r HTTPResponse) GetStreamKey() string {
	return r.StreamID.String() + ":" + strconv.Itoa(r.Seq)
}

// Represents metadata from an observed TLS 1.2 or 1.3 Client Hello message.
type TLSClientHello struct {
	// Identifies the TCP connection to which this message belongs.
	ConnectionID uuid.UUID

	// The DNS hostname extracted from the SNI extension, if any.
	Hostname *string

	// The list of protocols supported by the client, as seen in the ALPN
	// extension.
	SupportedProtocols []string
}

var _ ParsedNetworkContent = (*TLSClientHello)(nil)

func (TLSClientHello) ReleaseBuffers() {}

// Represents metadata from an observed TLS 1.2 or 1.3 Server Hello message.
type TLSServerHello struct {
	// Identifies the TCP connection to which this message belongs.
	ConnectionID uuid.UUID

	// The inferred TLS version.
	Version TLSVersion

	// The selected application-layer protocol, as seen in the ALPN extension, if
	// any.
	SelectedProtocol *string

	// The DNS host names appearing in the SAN extensions of the server's
	// certificate, if observed. The server's certificate is encrypted in TLS 1.3,
	// so this is only populated for TLS 1.2 connections.
	DNSNames []string
}

var _ ParsedNetworkContent = (*TLSServerHello)(nil)

func (TLSServerHello) ReleaseBuffers() {}

// Metadata from an observed TLS handshake.
type TLSHandshakeMetadata struct {
	// Uniquely identifies the underlying TCP connection.
	ConnectionID uuid.UUID

	// The inferred TLS version. Only populated if the Server Hello was seen.
	Version *TLSVersion

	// The DNS hostname extracted from the client's SNI extension, if any.
	SNIHostname *string

	// The list of protocols supported by the client, as seen in the ALPN
	// extension.
	SupportedProtocols []string

	// The selected application-layer protocol, as seen in the server's ALPN
	// extension, if any.
	SelectedProtocol *string

	// The SANs seen in the server's certificate. The server's certificate is
	// encrypted in TLS 1.3, so this is only populated for TLS 1.2 connections.
	SubjectAlternativeNames []string

	clientHandshakeSeen bool
	serverHandshakeSeen bool
}

var _ ParsedNetworkContent = (*TLSHandshakeMetadata)(nil)

func (TLSHandshakeMetadata) ReleaseBuffers() {}

func (tls *TLSHandshakeMetadata) HandshakeComplete() bool {
	return tls.clientHandshakeSeen && tls.serverHandshakeSeen
}

func (tls *TLSHandshakeMetadata) AddClientHello(hello *TLSClientHello) error {
	if tls.ConnectionID != hello.ConnectionID {
		return errors.Errorf("mismatched connections: %s and %s", tls.ConnectionID.String(), hello.ConnectionID.String())
	}

	if tls.clientHandshakeSeen {
		return errors.Errorf("multiple client handshakes seen for connection %s", tls.ConnectionID.String())
	}
	tls.clientHandshakeSeen = true

	// Copy the information in the given Client Hello, in case it is later
	// changed.

	if hello.Hostname != nil {
		hostname := *hello.Hostname
		tls.SNIHostname = &hostname
	}

	tls.SupportedProtocols = append(tls.SupportedProtocols, hello.SupportedProtocols...)

	return nil
}

func (tls *TLSHandshakeMetadata) AddServerHello(hello *TLSServerHello) error {
	if tls.ConnectionID != hello.ConnectionID {
		return errors.Errorf("mismatched connections: %s and %s", tls.ConnectionID.String(), hello.ConnectionID.String())
	}

	if tls.serverHandshakeSeen {
		return errors.Errorf("multiple server handshakes seen for connection %s", tls.ConnectionID.String())
	}
	tls.serverHandshakeSeen = true

	// Make local copies of the information in the given Server Hello, in case it
	// is later changed.

	version := hello.Version
	tls.Version = &version

	if hello.SelectedProtocol != nil {
		protocol := *hello.SelectedProtocol
		tls.SelectedProtocol = &protocol
	}

	tls.SubjectAlternativeNames = append(tls.SubjectAlternativeNames, hello.DNSNames...)

	return nil
}

// Determines whether the response latency in the application layer can be
// measured.
func (tls *TLSHandshakeMetadata) ApplicationLatencyMeasurable() bool {
	// For now, just determine whether the application layer carries HTTP 1.1
	// traffic.

	if !tls.HandshakeComplete() {
		return false
	}

	clientALPNHasHTTP1_1 := false
	clientALPNHasHTTP2 := false
	clientALPNHasUnknownProtocol := false
	for _, protocol := range tls.SupportedProtocols {
		switch protocol {
		case "http/1.1":
			clientALPNHasHTTP1_1 = true
		case "h2":
			clientALPNHasHTTP2 = true
		default:
			clientALPNHasUnknownProtocol = true
		}
	}

	if !clientALPNHasHTTP1_1 {
		// Client doesn't support HTTP 1.1. Conservatively return false.
		return false
	}

	if !clientALPNHasHTTP2 && !clientALPNHasUnknownProtocol {
		// Client only supports HTTP 1.1. Measurable.
		return true
	}

	// Client supports HTTP 1.1 and some other protocols. We need the server's
	// selection to figure out the application-layer protocol, but this is
	// encrypted in TLS 1.3. If we have anything but TLS 1.2, conservatively
	// return false.
	if tls.Version == nil || *tls.Version != TLS_v1_2 {
		return false
	}

	if tls.SelectedProtocol == nil {
		// Server did not explicitly select a protocol. If the client indicated any
		// unknown protocols, conservatively return false.

		// Client indicated both HTTP 1.1 and HTTP 2. The server hasn't explicitly
		// selected a protocol, so the client will expect HTTP 1.1.
		return !clientALPNHasUnknownProtocol
	}

	return *tls.SelectedProtocol == "http/1.1"
}

// Represents an observed HTTP/2 connection preface; no data from it
// is stored.
type HTTP2ConnectionPreface struct {
}

func (HTTP2ConnectionPreface) ReleaseBuffers() {}

// Represents an observed QUIC handshake (initial packet).
// Currently empty because we're only interested in the presence
// of QUIC traffic, not its payload.
type QUICHandshakeMetadata struct {
}

func (QUICHandshakeMetadata) ReleaseBuffers() {}
