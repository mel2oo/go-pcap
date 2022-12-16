package gopcap

import (
	"context"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// pcap reader interface
type Reader interface {
	Packets(ctx context.Context) (<-chan gopacket.Packet, error)
}

// pcap file to reader
type PcapFile struct {
	name string
}

func NewPcapFile(pcapname string) Reader {
	return &PcapFile{
		name: pcapname,
	}
}

func (p *PcapFile) Packets(ctx context.Context) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(p.name)
	if err != nil {
		panic(err)
	}

	out := make(chan gopacket.Packet)
	go func() {
		defer handle.Close()
		defer close(out)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			select {
			case <-ctx.Done():
				return
			case out <- packet:
			}
		}
	}()

	return out, nil
}
