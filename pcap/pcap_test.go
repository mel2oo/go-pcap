package pcap

import (
	"fmt"
	"testing"

	"github.com/mel2oo/go-pcap/gnet"
	ghttp "github.com/mel2oo/go-pcap/gnet/http"
	gtls "github.com/mel2oo/go-pcap/gnet/tls"
	"github.com/mel2oo/go-pcap/mempool"
)

func TestPcapParse(t *testing.T) {
	filename := "../testdata/79c29c05-a337-414f-b6f7-7f7ba2089042.pcap"

	pool, err := mempool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Error(err)
	}

	ntp := NewNetworkTrafficParser(1)
	ntp.pcap = FilePcapWrapper(filename)

	done := make(chan struct{})
	defer close(done)

	out, err := ntp.ParseFromInterface("", "", done,
		ghttp.NewHTTPRequestParserFactory(pool),
		ghttp.NewHTTPResponseParserFactory(pool),
		// ghttp2.NewHTTP2PrefaceParserFactory(),
		gtls.NewTLSClientParserFactory(),
		gtls.NewTLSServerParserFactory(),
	)
	if err != nil {
		t.Fail()
	}

	collected := []gnet.ParsedNetworkTraffic{}
	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
			c.Content.ReleaseBuffers()
			continue
		}

		// ignore ipv6
		if c.NetworkLayerType == gnet.IPv6 {
			c.Content.ReleaseBuffers()
			continue
		}

		collected = append(collected, c)
	}

	for index, c := range collected {
		fmt.Printf("index:%d src: %s:%d -> des: %s:%d %s\n",
			index, c.SrcIP.String(), c.SrcPort,
			c.DstIP.String(), c.DstPort, c.Content.Print())
	}
}
