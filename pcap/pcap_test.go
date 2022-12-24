package pcap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mel2oo/go-pcap/gnet"
	ghttp "github.com/mel2oo/go-pcap/gnet/http"
	"github.com/mel2oo/go-pcap/mempool"
)

func TestPcapParse(t *testing.T) {
	pool, err := mempool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Error(err)
	}

	traffic, err := NewTrafficParser(
		WithReadName("../testdata/con2dns1.pcap", false),
		WithStreamCloseTimeout(int64(time.Second)*300),
		WithStreamFlushTimeout(int64(time.Second)*300),
	)
	if err != nil {
		t.Error(err)
	}

	out, err := traffic.Parse(context.TODO(),
		ghttp.NewHTTPRequestParserFactory(pool),
		ghttp.NewHTTPResponseParserFactory(pool),
		// ghttp2.NewHTTP2PrefaceParserFactory(),
		// gtls.NewTLSClientParserFactory(),
		// gtls.NewTLSServerParserFactory(),
	)
	if err != nil {
		t.Error(err)
	}

	tcps := make(map[string][]gnet.NetTraffic)

	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		// if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
		// 	c.Content.ReleaseBuffers()
		// 	continue
		// }

		if c.LayerType == "TCP" {
			_, ok := tcps[c.ConnectionID.String()]
			if !ok {
				tcps[c.ConnectionID.String()] = make([]gnet.NetTraffic, 0)
			}

			if len(c.Payload) > 0 {
				tcps[c.ConnectionID.String()] = append(tcps[c.ConnectionID.String()], c)
			}
		}
	}

	fmt.Println(tcps)
}
