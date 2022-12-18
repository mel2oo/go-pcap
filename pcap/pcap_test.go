package pcap

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/gopacket/layers"
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
		WithReadName("../testdata/99e628ca-8160-4108-bb92-1bf38984331c.pcap", false),
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

		// ignore ipv6
		if c.LayerClass != nil {
			c.LayerClass.LayerTypes()
			if c.LayerClass.Contains(layers.LayerTypeIPv6) {
				c.Content.ReleaseBuffers()
				continue
			}
		}

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
