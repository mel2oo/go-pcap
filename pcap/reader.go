package pcap

import (
	"context"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type PcapReader interface {
	Capture(ctx context.Context) (<-chan gopacket.Packet, error)
}

// Read packet from pcap file.
type FileReader struct {
	PcapFile string
	BPFilter string
}

func NewFileReader(pcapfile, bpfilter string) *FileReader {
	return &FileReader{
		PcapFile: pcapfile,
		BPFilter: bpfilter,
	}
}

func (f FileReader) Capture(ctx context.Context) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(f.PcapFile)
	if err != nil {
		return nil, err
	}

	if len(f.BPFilter) > 0 {
		if err := handle.SetBPFFilter(f.BPFilter); err != nil {
			handle.Close()
			return nil, err
		}
	}

	out := make(chan gopacket.Packet, 10)

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

// Read packet from real device.
type DeviceReader struct {
	DeviceName string
	BPFilter   string
}

func NewDeviceReader(devicename, bpfilter string) *DeviceReader {
	return &DeviceReader{
		DeviceName: devicename,
		BPFilter:   bpfilter,
	}
}

func (d DeviceReader) Capture(ctx context.Context) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenLive(d.DeviceName, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if len(d.BPFilter) > 0 {
		if err := handle.SetBPFFilter(d.BPFilter); err != nil {
			handle.Close()
			return nil, err
		}
	}

	// Creating the packet source takes some time - do it here so the caller can
	// be confident that pakcets are being watched after this function returns.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Tune the packet channel buffer
	out := make(chan gopacket.Packet, 10)
	go func() {
		// Closing the handle can take a long time, so we close wrappedChan first to
		// allow the packet consumer to advance with its processing logic while we
		// wait for the handle to close in this goroutine.
		defer handle.Close()
		defer close(out)

		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-packetChan:
				if !ok {
					return
				}
				out <- pkt
			}
		}
	}()

	return out, nil
}
