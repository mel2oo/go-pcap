package http

import (
	"fmt"

	"github.com/google/gopacket/reassembly"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/mempool"
	"github.com/mel2oo/go-pcap/memview"
)

// Returns a factory for creating HTTP requests whose bodies will be allocated
// from the given buffer pool.
func NewHTTPRequestParserFactory(pool mempool.BufferPool) gnet.TCPParserFactory {
	return httpRequestParserFactory{
		bufferPool: pool,
	}
}

// Returns a factory for creating HTTP responses whose bodies will be allocated
// from the given buffer pool.
func NewHTTPResponseParserFactory(pool mempool.BufferPool) gnet.TCPParserFactory {
	return httpResponseParserFactory{
		bufferPool: pool,
	}
}

type httpRequestParserFactory struct {
	bufferPool mempool.BufferPool
}

func (httpRequestParserFactory) Name() string {
	return "HTTP/1.x Request Parser Factory"
}

func (httpRequestParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	defer func() {
		if decision == gnet.NeedMoreData && isEnd {
			decision = gnet.Reject
			discardFront = input.Len()
		}
	}()

	if input.Len() < minSupportedHTTPMethodLength {
		return gnet.NeedMoreData, 0
	}

	for _, m := range supportedHTTPMethods {
		if start := input.Index(0, []byte(m)); start >= 0 {
			d := hasValidHTTPRequestLine(input.SubView(start+int64(len(m)), input.Len()))
			switch d {
			case gnet.Accept:
				return gnet.Accept, start
			case gnet.NeedMoreData:
				return gnet.NeedMoreData, start
			}
		}
	}
	// Handle the case where the suffix of input is a prefix of the method in a
	// HTTP request line (e.g.  input=`<garbage>GE` where the next input is
	// `T / HTTP/1.1`.
	if input.Len() < maxSupportedHTTPMethodLength {
		return gnet.NeedMoreData, 0
	}
	return gnet.Reject, input.Len()
}

func (f httpRequestParserFactory) CreateParser(id gnet.TCPBidiID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newHTTPParser(true, id, seq, ack, f.bufferPool)
}

type httpResponseParserFactory struct {
	bufferPool mempool.BufferPool
}

func (httpResponseParserFactory) Name() string {
	return "HTTP/1.x Response Parser Factory"
}

func (httpResponseParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	defer func() {
		if decision == gnet.NeedMoreData && isEnd {
			decision = gnet.Reject
			discardFront = input.Len()
		}
	}()

	if input.Len() < minHTTPResponseStatusLineLength {
		return gnet.NeedMoreData, 0
	}

	for _, v := range []string{"HTTP/1.1", "HTTP/1.0"} {
		if start := input.Index(0, []byte(v)); start >= 0 {
			switch hasValidHTTPResponseStatusLine(input.SubView(start+int64(len(v)), input.Len())) {
			case gnet.Accept:
				return gnet.Accept, start
			case gnet.NeedMoreData:
				return gnet.NeedMoreData, start
			}
		}
	}
	return gnet.Reject, input.Len()
}

func (f httpResponseParserFactory) CreateParser(id gnet.TCPBidiID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newHTTPParser(false, id, seq, ack, f.bufferPool)
}

// Checks whether there is a valid HTTP request line as defiend in RFC 2616
// Section 5. The input should start right after the HTTP method.
func hasValidHTTPRequestLine(input memview.MemView) gnet.AcceptDecision {
	if input.Len() == 0 {
		return gnet.NeedMoreData
	}

	// A space separates the HTTP method from Request-URI.
	if input.GetByte(0) != ' ' {
		fmt.Println("rejecting HTTP request: lack of space between HTTP method and request-URI")
		return gnet.Reject
	}

	nextSP := input.Index(1, []byte(" "))
	if nextSP < 0 {
		// Could be dealing with a very long request URI.
		if input.Len()-1 > maxHTTPRequestURILength {
			fmt.Println("rejecting potential HTTP request with request URI longer than", maxHTTPRequestURILength)
			return gnet.Reject
		}
		return gnet.NeedMoreData
	} else if nextSP == 1 {
		fmt.Println("rejecting HTTP request: two spaces after HTTP method")
		return gnet.Reject
	}

	// Need at least 10 bytes to get the HTTP version on tail of the request line,
	// for example `HTTP/1.x\r\n`
	tail := input.SubView(nextSP+1, input.Len())
	if tail.Len() < 10 {
		return gnet.NeedMoreData
	}
	if tail.Index(0, []byte("HTTP/1.1\r\n")) == 0 || tail.Index(0, []byte("HTTP/1.0\r\n")) == 0 {
		return gnet.Accept
	}
	fmt.Println("rejecting HTTP request: request line does not end with HTTP version")
	return gnet.Reject
}

// Checks whether there is a valid HTTP response status line as defiend in
// RFC 2616 Section 6.1. The input should start right after the HTTP version.
func hasValidHTTPResponseStatusLine(input memview.MemView) gnet.AcceptDecision {
	if input.Len() < 5 {
		// Need a 2 spaces plus 3 bytes for status code.
		return gnet.NeedMoreData
	}

	// A space separates the HTTP version from status code.
	// The format is SP Status-Code SP Reason-Phrase CR LF
	if input.GetByte(0) != ' ' || input.GetByte(4) != ' ' {
		return gnet.Reject
	}

	// Bytes 1-3 should be in [0-9] for HTTP status code. We don't check that the
	// first digit is in [1-5] to allow custom status codes.
	if !isASCIIDigit(input.GetByte(1)) || !isASCIIDigit(input.GetByte(2)) || !isASCIIDigit(input.GetByte(3)) {
		return gnet.Reject
	}

	if input.Index(0, []byte("\r\n")) < 0 {
		// Could be dealing with a very long reason phrase.
		if input.Len()-4 > maxHTTPReasonPhraseLength {
			fmt.Println("rejecting potential HTTP response with reason phrase longer than", maxHTTPReasonPhraseLength)
			return gnet.Reject
		}
		return gnet.NeedMoreData
	}

	return gnet.Accept
}

func isASCIIDigit(b byte) bool {
	return '0' <= rune(b) && rune(b) <= '9'
}
