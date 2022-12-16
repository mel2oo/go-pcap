package gopcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type tcpStreamFactory struct {
}

func newTCPStreamFactory() *tcpStreamFactory {
	return &tcpStreamFactory{}
}

func (fact *tcpStreamFactory) New(netFlow, tcpFlow gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	// return newTCPStream(fact.clock, netFlow, fact.outChan, fact.fs)
	return nil
}
