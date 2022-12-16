package gnet

import (
	"testing"

	"github.com/google/gopacket/reassembly"
	"github.com/mel2oo/go-pcap/memview"
)

type testFactory struct {
	decision     AcceptDecision
	discardFront int64
}

func (testFactory) Name() string {
	return "testFactory"
}

func (f testFactory) Accepts(memview.MemView, bool) (AcceptDecision, int64) {
	return f.decision, f.discardFront
}

func (f testFactory) CreateParser(_ TCPBidiID, _, _ reassembly.Sequence) TCPParser {
	return nil
}

func TestTCPParserFactorySelector(t *testing.T) {
	testInput := memview.New([]byte("hello I'm test input"))

	testCases := []struct {
		name                 string
		facts                []TCPParserFactory
		expectedDecision     AcceptDecision
		expectedDiscardFront int64
	}{
		{
			name:                 "no factories",
			facts:                []TCPParserFactory{},
			expectedDecision:     Reject,
			expectedDiscardFront: testInput.Len(),
		},
		{
			name: "Accept",
			facts: []TCPParserFactory{
				testFactory{Accept, 6},
				testFactory{NeedMoreData, 1},
				testFactory{Reject, testInput.Len()},
			},
			expectedDecision:     Accept,
			expectedDiscardFront: 6,
		},
		{
			name: "single NeedMoreData",
			facts: []TCPParserFactory{
				testFactory{Reject, testInput.Len()},
				testFactory{NeedMoreData, 1},
				testFactory{Reject, testInput.Len()},
			},
			expectedDecision:     NeedMoreData,
			expectedDiscardFront: 1,
		},
		{
			name: "multiple NeedMoreData take min discard",
			facts: []TCPParserFactory{
				testFactory{Reject, testInput.Len()},
				testFactory{NeedMoreData, 1},
				testFactory{NeedMoreData, 10},
				testFactory{Reject, testInput.Len()},
			},
			expectedDecision:     NeedMoreData,
			expectedDiscardFront: 1,
		},
		{
			name: "reject return len of input",
			facts: []TCPParserFactory{
				testFactory{Reject, -1},
				testFactory{Reject, -1},
				testFactory{Reject, -1},
			},
			expectedDecision:     Reject,
			expectedDiscardFront: testInput.Len(),
		},
	}

	for _, c := range testCases {
		s := TCPParserFactorySelector(c.facts)
		_, d, df := s.Select(testInput, true)
		if c.expectedDecision != d {
			t.Errorf("[%s] expected decision %d, got %d", c.name, c.expectedDecision, d)
		}
		if c.expectedDiscardFront != df {
			t.Errorf("[%s] expected discard front %d, got %d", c.name, c.expectedDiscardFront, df)
		}
	}
}
