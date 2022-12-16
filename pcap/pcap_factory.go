package pcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/mel2oo/go-pcap/gnet"
)

// Internal implementation of reassembly.AssemblerContext that include TCP
// seq and ack numbers.
type assemblerCtxWithSeq struct {
	ci       gopacket.CaptureInfo
	seq, ack reassembly.Sequence
}

func contextFromTCPPacket(p gopacket.Packet, t *layers.TCP) *assemblerCtxWithSeq {
	return &assemblerCtxWithSeq{
		ci:  p.Metadata().CaptureInfo,
		seq: reassembly.Sequence(t.Seq),
		ack: reassembly.Sequence(t.Ack),
	}
}

func (ctx *assemblerCtxWithSeq) GetCaptureInfo() gopacket.CaptureInfo {
	return ctx.ci
}

// tcpStreamFactory implements reassembly.StreamFactory.
type tcpStreamFactory struct {
	fs      gnet.TCPParserFactorySelector
	outChan chan<- gnet.NetTraffic
}

func newTCPStreamFactory(outChan chan<- gnet.NetTraffic,
	fs gnet.TCPParserFactorySelector) *tcpStreamFactory {
	return &tcpStreamFactory{
		fs:      fs,
		outChan: outChan,
	}
}

func (fact *tcpStreamFactory) New(netFlow, tcpFlow gopacket.Flow, _ *layers.TCP,
	_ reassembly.AssemblerContext) reassembly.Stream {
	return newTCPStream(netFlow, fact.outChan, fact.fs)
}
