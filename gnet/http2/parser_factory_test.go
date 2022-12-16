package http2

import (
	"testing"

	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

// TODO: the nice "segment" utility from http/1 tests is not exported,
// so we have more manual splitting in place here.

func TestHTTP2Preface(t *testing.T) {
	testCases := []struct {
		Name             string
		VerbatimInput    [][]byte
		expectedDecision gnet.AcceptDecision
		expectedDF       int64
	}{
		{
			"whole at start",
			[][]byte{connectionPreface},
			gnet.Accept,
			0,
		},
		{
			"split in two",
			[][]byte{connectionPreface[0:8], connectionPreface[8:]},
			gnet.Accept,
			0,
		},
		{
			"junk before preface",
			[][]byte{[]byte("abcdef"), connectionPreface[0:8], connectionPreface[8:]},
			gnet.Accept,
			6,
		},
		{
			"junk before preface 2",
			[][]byte{[]byte("abcdefP"), connectionPreface[1:8], connectionPreface[8:]},
			gnet.Accept,
			6,
		},
		{
			"http/1.1 code",
			[][]byte{[]byte("GET /bulk/this/out/some/so/its/long HTTP/1.1\r\n")},
			gnet.Reject,
			46,
		},
	}

	fact := NewHTTP2PrefaceParserFactory()

	for _, tc := range testCases {
		var decision gnet.AcceptDecision
		var input memview.MemView
		var totalLen int64
		for i, b := range tc.VerbatimInput {
			totalLen += int64(len(b))
			input.Append(memview.New(b))

			atEnd := (i == len(tc.VerbatimInput)-1)
			d, df := fact.Accepts(input, atEnd)
			decision = d
			input = input.SubView(df, input.Len())
		}

		discardFront := totalLen - input.Len()
		if tc.expectedDecision != decision {
			t.Errorf("[%s] expected decision %s, got %s", tc.Name, tc.expectedDecision, decision)
		}
		if tc.expectedDF != discardFront {
			t.Errorf("[%s] expected discard front %d, got %d", tc.Name, tc.expectedDF, discardFront)
		}
	}
}
