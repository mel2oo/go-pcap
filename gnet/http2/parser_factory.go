package http2

import (
	"github.com/google/gopacket/reassembly"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

// This parser only recognizes HTTP/2 connection prefaces.
//
// The "client connection preface" is used with known HTTP/2
// servers, or after the negotiation with the 'Upgrade: h2c`
// header is completed.
func NewHTTP2PrefaceParserFactory() gnet.TCPParserFactory {
	return &http2PrefaceParserFactory{}
}

type http2PrefaceParserFactory struct {
}

func (http2PrefaceParserFactory) Name() string {
	return "HTTP/2 Connection Preface Parser Factory"
}

// 24 octets: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
var connectionPreface []byte = []byte{
	0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
	0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
	0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
}

var connectionPrefaceFirstByte []byte = connectionPreface[:1]

func (http2PrefaceParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < int64(len(connectionPreface)) {
		if isEnd {
			return gnet.Reject, input.Len()
		}
		return gnet.NeedMoreData, 0
	}

	if start := input.Index(0, connectionPreface); start >= 0 {
		return gnet.Accept, start
	}

	// If there is a partial match at the end of the stream, then we should
	// leave those bytes alone. Unfortunately, input.Index proved to be
	// too hard to adapt to return partial match locations (because bytes.Index
	// does not either) so here is a hack to avoid just returning (NeedMoreData, 23)
	// all the time. We'll just look for the first byte.
	if isEnd {
		return gnet.Reject, input.Len()
	}

	nMinus1Suffix := input.Len() - int64(len(connectionPreface)) + 1
	possible := input.Index(nMinus1Suffix, connectionPrefaceFirstByte)
	if possible >= 0 {
		return gnet.NeedMoreData, possible
	}
	return gnet.Reject, input.Len()
}

// Once we've found a HTTP/2 connection preface, the rest of the connection
// can be assumed to be HTTP/2 (or, I suppose, an error.)  There is no way
// to downgrade, so we can throw away all subsequent data.
type http2Sink struct {
	firstInput         bool
	totalBytesConsumed int64
}

func (http2PrefaceParserFactory) CreateParser(id gnet.TCPBidiID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return &http2Sink{
		firstInput: true,
	}
}

func (*http2Sink) Name() string {
	return "HTTP/2 sink"
}

func (s *http2Sink) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	// Return one event at the start of the stream, so we can count it.
	if s.firstInput {
		s.firstInput = false
		s.totalBytesConsumed = 0
		return gnet.HTTP2ConnectionPreface{}, memview.Empty(), input.Len(), nil
	}

	// The interface documentation says we must return a non-nil result or an
	// error when isEnd is true. I am violating that by returning nil, but the
	// code in stream.go can handle that, I believe.
	s.totalBytesConsumed += input.Len()
	return nil, memview.Empty(), s.totalBytesConsumed, nil
}
