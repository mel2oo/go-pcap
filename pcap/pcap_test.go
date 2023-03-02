package pcap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/gnet/ctp"
	ghttp "github.com/mel2oo/go-pcap/gnet/http"
	gtls "github.com/mel2oo/go-pcap/gnet/tls"
	"github.com/mel2oo/go-pcap/mempool"
	"github.com/mel2oo/go-pcap/pcap/ja3"
)

func TestPcapParse(t *testing.T) {
	pool, err := mempool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Error(err)
	}

	traffic, err := NewTrafficParser(
		WithReadName("../testdata/dump.pcap", false),
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
	dnss := make([]gnet.NetTraffic, 0)
	http := make([]gnet.NetTraffic, 0)

	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
			c.Content.ReleaseBuffers()
			continue
		}

		if c.LayerType == "TCP" {
			_, ok := tcps[c.ConnectionID.String()]
			if !ok {
				tcps[c.ConnectionID.String()] = make([]gnet.NetTraffic, 0)
			}

			tcps[c.ConnectionID.String()] = append(tcps[c.ConnectionID.String()], c)

			_, ok1 := c.Content.(gnet.HTTPRequest)
			_, ok2 := c.Content.(gnet.HTTPResponse)
			if ok1 || ok2 {
				http = append(http, c)
			}

		} else if c.LayerType == "DNS" {
			dnss = append(dnss, c)
		} else if c.LayerType == "ICMPv4" {
			fmt.Println()
		}
	}

	for _, h := range http {
		r, ok := h.Content.(gnet.HTTPRequest)
		if !ok {
			continue
		}

		fmt.Println("url:", r.URL.String())
	}

	fmt.Println(tcps)
	fmt.Println(dnss)
	fmt.Println(http)
}

func TestTLS(t *testing.T) {
	traffic, err := NewTrafficParser(
		WithReadName("../testdata/dump.pcap", false),
		WithStreamCloseTimeout(int64(time.Second)*300),
		WithStreamFlushTimeout(int64(time.Second)*300),
	)
	if err != nil {
		t.Error(err)
	}

	out, err := traffic.Parse(context.TODO(),
		gtls.NewTLSClientParserFactory(),
		gtls.NewTLSServerParserFactory(),
	)
	if err != nil {
		t.Error(err)
	}

	tcps := make(map[string][]gnet.NetTraffic)
	tlss := make([]gnet.NetTraffic, 0)

	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
			c.Content.ReleaseBuffers()
			continue
		}

		if c.LayerType == "TCP" {
			_, ok := tcps[c.ConnectionID.String()]
			if !ok {
				tcps[c.ConnectionID.String()] = make([]gnet.NetTraffic, 0)
			}

			tcps[c.ConnectionID.String()] = append(tcps[c.ConnectionID.String()], c)

			// TLS
			_, ok1 := c.Content.(gnet.TLSClientHello)
			_, ok2 := c.Content.(gnet.TLSServerHello)
			if ok1 || ok2 {
				tlss = append(tlss, c)
			}
		}
	}

	for _, t := range tlss {
		switch ch := t.Content.(type) {
		case gnet.TLSClientHello:
			fin, md5 := ja3.GetJa3Hash(ch)
			fmt.Printf("client id:%s src:%s dst:%s ja3:%s md5:%s\n",
				t.ConnectionID.String(), t.SrcIP.String(), t.DstIP.String(), fin, md5)
		case gnet.TLSServerHello:
			fin, md5 := ja3.GetJa3SHash(ch)
			fmt.Printf("server id:%s src:%s dst:%s ja3s:%s md5:%s\n",
				t.ConnectionID.String(), t.SrcIP.String(), t.DstIP.String(), fin, md5)
		}
	}
}

func TestFTP(t *testing.T) {
	traffic, err := NewTrafficParser(
		WithReadName("../testdata/ftp.pcapng", false),
		WithStreamCloseTimeout(int64(time.Second)*300),
		WithStreamFlushTimeout(int64(time.Second)*300),
	)
	if err != nil {
		t.Error(err)
	}

	out, err := traffic.Parse(context.TODO(),
		ctp.NewCtpRequestParserFactory(),
		ctp.NewCtpResponseParserFactory(),
	)
	if err != nil {
		t.Error(err)
	}

	tcps := make(map[string][]gnet.NetTraffic)
	ftps := make([]gnet.NetTraffic, 0)

	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
			c.Content.ReleaseBuffers()
			continue
		}

		if c.LayerType == "TCP" {
			_, ok := tcps[c.ConnectionID.String()]
			if !ok {
				tcps[c.ConnectionID.String()] = make([]gnet.NetTraffic, 0)
			}

			tcps[c.ConnectionID.String()] = append(tcps[c.ConnectionID.String()], c)

			_, ok1 := c.Content.(gnet.FtpSmtpRequest)
			_, ok2 := c.Content.(gnet.FtpSmtpResponse)
			if ok1 || ok2 {
				ftps = append(ftps, c)
			}
		}
	}

	for _, f := range ftps {
		switch ff := f.Content.(type) {
		case gnet.FtpSmtpRequest:
			t.Logf("(%s) cmd: %s arg: %s\n", ff.ConnectionID, ff.CMD, ff.Arg)
		case gnet.FtpSmtpResponse:
			t.Logf("(%s) code: %s arg: %s", ff.ConnectionID, ff.Code, ff.Arg)
		}
	}
}

func TestSMTP(t *testing.T) {
	traffic, err := NewTrafficParser(
		WithReadName("../testdata/smtp-normal.pcapng", false),
		WithStreamCloseTimeout(int64(time.Second)*300),
		WithStreamFlushTimeout(int64(time.Second)*300),
	)
	if err != nil {
		t.Error(err)
	}

	out, err := traffic.Parse(context.TODO(),
		ctp.NewCtpRequestParserFactory(),
		ctp.NewCtpResponseParserFactory(),
	)
	if err != nil {
		t.Error(err)
	}

	tcps := make(map[string][]gnet.NetTraffic)
	ftps := make([]gnet.NetTraffic, 0)

	for c := range out {
		// Remove TCP metadata, which was added after this test was written.
		if _, ignore := c.Content.(gnet.TCPPacketMetadata); ignore {
			c.Content.ReleaseBuffers()
			continue
		}

		if c.LayerType == "TCP" {
			_, ok := tcps[c.ConnectionID.String()]
			if !ok {
				tcps[c.ConnectionID.String()] = make([]gnet.NetTraffic, 0)
			}

			tcps[c.ConnectionID.String()] = append(tcps[c.ConnectionID.String()], c)

			_, ok1 := c.Content.(gnet.FtpSmtpRequest)
			_, ok2 := c.Content.(gnet.FtpSmtpResponse)
			if ok1 || ok2 {
				ftps = append(ftps, c)
			}
		}
	}

	for _, f := range ftps {
		switch ff := f.Content.(type) {
		case gnet.FtpSmtpRequest:
			t.Logf("(%s) cmd: %s arg: %s\n", ff.ConnectionID, ff.CMD, ff.Arg)
		case gnet.FtpSmtpResponse:
			t.Logf("(%s) code: %s arg: %s", ff.ConnectionID, ff.Code, ff.Arg)
		}
	}
}
