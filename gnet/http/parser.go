package http

import (
	"bufio"
	"io"
	"net/http"

	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/mempool"
	"github.com/mel2oo/go-pcap/memview"
	"github.com/pkg/errors"
)

var (
	// Default maximum HTTP length supported.
	// Can be altered by the CLI as a configuration setting, but doing so after parsing
	// has started will be a race condition.
	MaximumHTTPLength int64 = 1024 * 1024
)

// Parses a single HTTP request or response.
//
// Internally, this uses Go's HTTP parser. Go's parser is a synchronous one; we
// convert it into an asynchronous one by running it in a goroutine.
type httpParser struct {
	// For sending incoming bytes to the parser goroutine.
	w *io.PipeWriter

	// The total number of bytes consumed from the stream being parsed.
	totalBytesConsumed int64

	// When anything is written to this channel, it indicates that the parser
	// goroutine is done. The value written is the resulting error, if any.
	readClosed chan error

	// When anything is written to this channel, it indicates that the parser
	// goroutine is done. The value written is the result of the parsing: an HTTP
	// request or response.
	resultChan chan gnet.ParsedNetworkContent

	// Indicates whether this parser is for a request or a response.
	isRequest bool

	// Maximum length of HTTP request or response supported; larger requests or
	// responses may be truncated.
	maxHttpLength int64
}

var _ gnet.TCPParser = (*httpParser)(nil)

func (p *httpParser) Name() string {
	if p.isRequest {
		return "HTTP/1.x Request Parser"
	}
	return "HTTP/1.x Response Parser"
}

func (p *httpParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	var consumedBytes int64
	defer func() {
		totalBytesConsumed = p.totalBytesConsumed

		if err == nil {
			return
		}

		// Adjust the number of bytes that were read by the reader but were unused.
		switch e := err.(type) {
		case httpPipeReaderDone:
			result = <-p.resultChan
			unused = input.SubView(consumedBytes-int64(e), input.Len())
			totalBytesConsumed -= unused.Len()
			err = nil
		case httpPipeReaderError:
			err = e.err
		default:
			err = errors.Wrap(err, "encountered unknown HTTP pipe reader error")
		}
	}()

	p.totalBytesConsumed += input.Len()

	// The PipeWriter blocks until the reader is done consuming all the bytes.
	consumedBytes, err = io.Copy(p.w, input.CreateReader())
	if err != nil {
		return
	}

	// The reader might close (aka parse complete) after the write returns, so we
	// need to check. We force an empty write such that:
	// - If the parse is indeed complete, the reader no longer consumes anything,
	// 	 so this call will block until the reader closes.
	// - If the parse is not done yet, the empty write doesn't change things.
	_, err = p.w.Write([]byte{})
	if err != nil {
		return
	}

	// If the reader has not closed yet, tell it we have no more input. This case
	// happens if there's no content-length and we're reading until connection
	// close.
	//
	// Also, if the HTTP request or response is longer than our maximum length,
	// close the pipe anyway. This will leave the input stream in a state where it
	// probably can't find the next header until the accumulated data in the
	// reassembly buffer is all skipped.
	if isEnd || p.totalBytesConsumed > p.maxHttpLength {
		p.w.Close()
		err = <-p.readClosed
	}

	return
}

func newHTTPParser(isRequest bool, bidiID uuid.UUID, seq, ack reassembly.Sequence, pool mempool.BufferPool) *httpParser {
	// Unfortunately, go's http request parser blocks. So we need to run it in a
	// separate goroutine. This needs to be addressed as part of
	// https://app.clubhouse.io/akita-software/story/600

	// The channel on which the parsed HTTP request or response is sent.
	resultChan := make(chan gnet.ParsedNetworkContent)
	readClosed := make(chan error, 1)
	r, w := io.Pipe()
	go func() {
		var req *http.Request
		var resp *http.Response
		var err error
		br := bufio.NewReader(r)

		// Create a buffer for the body.
		//
		// XXX This is used in a very non-local fashion. Consumers of the body are
		// responsible for resetting the buffer, but there is no way to guarantee
		// that this will happen.
		body := pool.NewBuffer()

		if isRequest {
			req, err = readSingleHTTPRequest(br, body)
		} else {
			resp, err = readSingleHTTPResponse(br, body)
		}
		if err != nil {
			err = httpPipeReaderError{
				err:         err,
				unusedBytes: int64(br.Buffered()),
			}
			r.CloseWithError(err)
			readClosed <- err
			body.Release()
			return
		}

		// Close the reader to signal to the pipe writer that result is ready.
		err = httpPipeReaderDone(br.Buffered())
		r.CloseWithError(err)
		readClosed <- err

		var c gnet.ParsedNetworkContent
		if isRequest {
			// Because HTTP requires the request to finish before sending a response,
			// TCP ack number on the first segment of the HTTP request is equal to the
			// TCP seq number on the first segment of the corresponding HTTP response.
			// Hence we use it to differntiate differnt pairs of HTTP request and
			// response on the same TCP stream.
			c = gnet.FromStdRequest(uuid.UUID(bidiID), int(ack), req, body)
		} else {
			// Because HTTP requires the request to finish before sending a response,
			// TCP ack number on the first segment of the HTTP request is equal to the
			// TCP seq number on the first segment of the corresponding HTTP response.
			// Hence we use it to differntiate differnt pairs of HTTP request and
			// response on the same TCP stream.
			c = gnet.FromStdResponse(uuid.UUID(bidiID), int(seq), resp, body)
		}
		resultChan <- c
	}()

	return &httpParser{
		w:             w,
		resultChan:    resultChan,
		readClosed:    readClosed,
		isRequest:     isRequest,
		maxHttpLength: MaximumHTTPLength,
	}
}

// Reads a single HTTP request, only consuming the exact number of bytes that
// form the request and its body, but there may be unused bytes left in the
// bufio.Reader's buffer. The request body is written into the given buffer.
func readSingleHTTPRequest(r *bufio.Reader, body mempool.Buffer) (*http.Request, error) {
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}

	req.URL.Scheme = "http"
	req.URL.Host = req.Host

	if req.Body == nil {
		return req, nil
	}

	// Read the body to move the reader's position to the end of the body.
	_, bodyErr := io.Copy(body, req.Body)
	req.Body.Close()

	switch {
	case
		errors.Is(bodyErr, io.ErrUnexpectedEOF),
		errors.Is(bodyErr, mempool.ErrEmptyPool):

		// Let the next level try to handle a body that was truncated.
		bodyErr = nil
	}

	return req, bodyErr
}

// Reads a single HTTP response, only consuming the exact number of bytes that
// form the response and its body, but there may be unused bytes left in the
// bufio.Reader's buffer. The response body is written into the given buffer.
func readSingleHTTPResponse(r *bufio.Reader, body mempool.Buffer) (*http.Response, error) {
	// XXX BUG Because a nil http.Request is provided to ReadResponse, the http
	// library assumes a GET request. If this is actually a response to a HEAD
	// request and the Content-Length header is present, the library will treat
	// the bytes after the end of the response as a response body.
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}

	if resp.Body == nil {
		return resp, nil
	}

	// Read the body to move the reader's position to the end of the body.
	_, bodyErr := io.Copy(body, resp.Body)
	resp.Body.Close()

	switch {
	case
		errors.Is(bodyErr, io.ErrUnexpectedEOF),
		errors.Is(bodyErr, mempool.ErrEmptyPool):

		// Let the next level try to handle a body that was truncated.
		bodyErr = nil
	}

	return resp, bodyErr
}

// Indicates the pipe reader has successfully completed parsing. The integer
// specifies the number of bytes read from the pipe writer but were unused.
type httpPipeReaderDone int64

func (httpPipeReaderDone) Error() string {
	return "HTTP pipe reader success"
}

type httpPipeReaderError struct {
	err         error // the actual err
	unusedBytes int64 // number of bytes read from the pipe writer but were unused
}

func (e httpPipeReaderError) Error() string {
	return e.err.Error()
}
