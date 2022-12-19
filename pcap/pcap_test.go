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
		WithReadName("../testdata/tcp.pcap", false),
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

	collected := []gnet.NetTraffic{}
	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
			c.Content.ReleaseBuffers()
			continue
		}

		if len(c.LayerType) == 0 {
			continue
		}

		if c.LayerType == "UDP" {
			continue
		}

		// if net.IsIPv6(c.SrcIP) {
		// 	continue
		// }

		collected = append(collected, c)
	}

	size := 0
	for _, c := range collected {
		// if strings.Contains(c.Content.Print(), "HTTP") {
		// 	size += 1
		// }
		if _, ok := c.Content.(gnet.HTTPRequest); ok {
			size += 1
		}

		// if _, ok := c.Content.(gnet.HTTPResponse); ok {
		// 	size += 1
		// }

		// fmt.Printf("index:%d src: %s:%d -> des: %s:%d %s\n",
		// 	index, c.SrcIP.String(), c.SrcPort,
		// 	c.DstIP.String(), c.DstPort, c.Content.Print())
	}

	fmt.Println(size)
}
