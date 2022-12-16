package http

import (
	"fmt"
	"testing"

	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/mempool"
	"github.com/mel2oo/go-pcap/memview"
)

type acceptTestCase struct {
	name string
	// input will get segmented in O(n^3) different ways to test robustness. Use
	// verbatimInput instead of large inputs.
	input string
	// verbatimInput will not get segmented.
	verbatimInput    []memview.MemView
	expectedDecision gnet.AcceptDecision
	expectedDF       int64 // expected discard front

	// Don't signal end of the stream for this test case
	dontMarkEnd bool
}

func runAcceptTest(isRequest bool, c acceptTestCase, pool mempool.BufferPool) error {
	var fact gnet.TCPParserFactory
	if isRequest {
		fact = NewHTTPRequestParserFactory(pool)
	} else {
		fact = NewHTTPResponseParserFactory(pool)
	}

	var segments <-chan []memview.MemView
	if c.verbatimInput != nil {
		s := make(chan []memview.MemView)
		segments = s
		go func() {
			s <- c.verbatimInput
			close(s)
		}()
	} else {
		segments = segment(c.input)
	}

	for mvs := range segments {
		var decision gnet.AcceptDecision
		var input memview.MemView
		var totalLen int64
		for i, mv := range mvs {
			totalLen += mv.Len()
			input.Append(mv)

			atEnd := (i == len(mvs)-1) && !c.dontMarkEnd
			d, df := fact.Accepts(input, atEnd)
			decision = d
			input = input.SubView(df, input.Len())
		}

		discardFront := totalLen - input.Len()
		if c.expectedDecision != decision {
			return fmt.Errorf("[%s] expected decision %s, got %s input=%s", c.name, c.expectedDecision, decision, dump(mvs))
		}
		if c.expectedDF != discardFront {
			return fmt.Errorf("[%s] expected discard front %d, got %d input=%s", c.name, c.expectedDF, discardFront, dump(mvs))
		}
	}
	return nil
}

func TestHTTPRequestParserFactoryAccepts(t *testing.T) {
	pool, err := mempool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Error(err)
	}

	testCases := []acceptTestCase{
		{
			name:             "accept without body",
			input:            "GET / HTTP/1.1\r\n",
			expectedDecision: gnet.Accept,
		},
		{
			name:             "accept with body",
			input:            "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nfoobar",
			expectedDecision: gnet.Accept,
		},
		{
			name:             "non-supported HTTP method",
			input:            "FOO / HTTP/1.1\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       16,
		},
		{
			name:             "non-supported HTTP version",
			input:            "GET / HTTP/0.3\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       16,
		},
		{
			name:             "HTTP method string in request URI OK",
			input:            "GET /POST/PUT HTTP/1.1\r\n",
			expectedDecision: gnet.Accept,
			expectedDF:       0,
		},
		{
			name: "accept long request-URI within limit",
			verbatimInput: []memview.MemView{
				memview.New([]byte("GET /" + randomString(maxHTTPRequestURILength-100))),
				memview.New([]byte(randomString(50))),
				memview.New([]byte(randomString(49) + " HTTP/1.1\r\n")),
			},
			expectedDecision: gnet.Accept,
			expectedDF:       0,
		},
		{
			name: "reject long request-URI beyond limit",
			verbatimInput: []memview.MemView{
				memview.New([]byte("GET /" + randomString(maxHTTPRequestURILength-100))),
				memview.New([]byte(randomString(500))), // should reach a reject here
			},
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("GET /") + maxHTTPRequestURILength - 100 + 500),
		},
		{
			name:             "reject stray bytes at end of request line",
			input:            "GET / HTTP/1.1withextrastuff\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       30,
		},
		{
			name:             "reject two spaces in a row after HTTP method",
			input:            "GET  / HTTP/1.1\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       17,
		},
		{
			name:             "reject garbage",
			input:            "hello I'm garbage\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("hello I'm garbage\r\n")),
		},
		{
			name:             "accept after discarding stray leading bytes",
			input:            "POSTGET / HTTP/1.1\r\n",
			expectedDecision: gnet.Accept,
			expectedDF:       int64(len("POST")),
		},
	}

	for _, c := range testCases {
		if err := runAcceptTest(true, c, pool); err != nil {
			t.Error(err)
		}
	}
}

func TestHTTPResponseParserFactoryAccepts(t *testing.T) {
	pool, err := mempool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Error(err)
	}

	testCases := []acceptTestCase{
		{
			name:             "accept without body",
			input:            "HTTP/1.1 200 OK\r\n",
			expectedDecision: gnet.Accept,
		},
		{
			name:             "accept with body",
			input:            "HTTP/1.1 200 OK\r\nhello",
			expectedDecision: gnet.Accept,
		},
		{
			name:             "reject invalid status code",
			input:            "HTTP/1.1 X99 OK\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       17,
		},
		{
			name: "accept long reason phrase within limit",
			verbatimInput: []memview.MemView{
				memview.New([]byte("HTTP/1.1 200 " + randomString(maxHTTPReasonPhraseLength-100))),
				memview.New([]byte(randomString(50))),
				memview.New([]byte(randomString(49) + "\r\n")),
			},
			expectedDecision: gnet.Accept,
		},
		{
			name: "reject long reason phrase outside of limit",
			verbatimInput: []memview.MemView{
				memview.New([]byte("HTTP/1.1 200 " + randomString(maxHTTPReasonPhraseLength-100))),
				memview.New([]byte(randomString(500))), // should get rejected here
			},
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("HTTP/1.1 200 ") + maxHTTPReasonPhraseLength - 100 + 500),
		},
		{
			name:             "reject no space between HTTP version and status code",
			input:            "HTTP/1.1200 OK\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("HTTP/1.1200 OK\r\n")),
		},
		{
			name:             "reject no space between status code and reason phrase",
			input:            "HTTP/1.1 200OK\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("HTTP/1.1 200OK\r\n")),
		},
		{
			name:             "reject unsupported HTTP version",
			input:            "HTTP/0.3 200 OK\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("HTTP/0.3 200 OK\r\n")),
		},
		{
			name:             "reject garbage",
			input:            "hello I'm garbage\r\n",
			expectedDecision: gnet.Reject,
			expectedDF:       int64(len("hello I'm garbage\r\n")),
		},
		{
			name:             "accept after discarding stray leading bytes",
			input:            "OKHTTP/1.1 200 OK\r\n",
			expectedDecision: gnet.Accept,
			expectedDF:       int64(len("OK")),
		},
		/*
			// Currently failing -- does not look for response that spans the end of
			// what is available.
			{
				name:             "more data needed after discarding stray leading bytes",
				input:            "ABCDEFGHIJKLMNOPQRSTUVWXYZ\nHTTP/",
				expectedDecision: gnet.NeedMoreData,
				expectedDF:       27,
				dontMarkEnd:      true,
			},
			{
				name:             "more data needed in reason phrase",
				input:            "xxxxxxxxxxxxxxxxxxxxxxxxxx\nHTTP/1.1 200 Everything is tip-top",
				expectedDecision: gnet.NeedMoreData,
				expectedDF:       27,
				dontMarkEnd:      true,
			},
			// Some segmentations work for this one, others fail
			{
				name:             "complete reason phrase after many stray leading bytes",
				input:            "xxxxxxxxxxxxxxxxxxxxxxxxxx\nHTTP/1.1 200 Everything is tip-top\r\n",
				expectedDecision: gnet.Accept,
				expectedDF:       27,
				dontMarkEnd:      true,
			},
		*/
	}

	for _, c := range testCases {
		if err := runAcceptTest(false, c, pool); err != nil {
			t.Error(err)
		}
	}
}
