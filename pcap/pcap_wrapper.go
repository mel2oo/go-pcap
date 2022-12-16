package pcap

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type pcapWrapper interface {
	capturePackets(done <-chan struct{}, interfaceName, bpfFilter string) (<-chan gopacket.Packet, error)
	getInterfaceAddrs(interfaceName string) ([]net.IP, error)
}

// pcapWrapper backed by a pcap file.
type FilePcapWrapper string

func (f FilePcapWrapper) capturePackets(done <-chan struct{}, _, _ string) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(string(f))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s", f)
	}

	out := make(chan gopacket.Packet)

	go func() {
		defer handle.Close()
		defer close(out)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			select {
			case <-done:
				return
			case out <- packet:
			}
		}
	}()

	return out, nil
}

func (FilePcapWrapper) getInterfaceAddrs(interfaceName string) ([]net.IP, error) {
	return nil, nil
}

type pcapImpl struct{}

func (p *pcapImpl) capturePackets(done <-chan struct{}, interfaceName, bpfFilter string) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenLive(interfaceName, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open pcap to %s", interfaceName)
	}
	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, errors.Wrap(err, "failed to set BPF filter")
		}
	}

	// Creating the packet source takes some time - do it here so the caller can
	// be confident that pakcets are being watched after this function returns.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktChan := packetSource.Packets()

	// TODO: tune the packet channel buffer
	wrappedChan := make(chan gopacket.Packet, 10)
	go func() {
		// Closing the handle can take a long time, so we close wrappedChan first to
		// allow the packet consumer to advance with its processing logic while we
		// wait for the handle to close in this goroutine.
		defer func() {
			close(wrappedChan)
			handle.Close()
		}()

		startTime := time.Now()
		count := 0
		for {
			select {
			case <-done:
				return
			case pkt, ok := <-pktChan:
				if ok {
					wrappedChan <- pkt

					if count == 0 {
						ttfp := time.Since(startTime)
						fmt.Printf("Time to first packet on %s: %s\n", interfaceName, ttfp)
					}
					count += 1
				} else {
					return
				}
			}
		}
	}()
	return wrappedChan, nil
}

func (p *pcapImpl) getInterfaceAddrs(interfaceName string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "no network interface with name %s", interfaceName)
	}

	hostIPs := []net.IP{}
	if addrs, err := iface.Addrs(); err != nil {
		return nil, errors.Wrapf(err, "failed to get addresses on interface %s", iface.Name)
	} else {
		for _, addr := range addrs {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				hostIPs = append(hostIPs, tcpAddr.IP)
			} else if udpAddr, ok := addr.(*net.UDPAddr); ok {
				hostIPs = append(hostIPs, udpAddr.IP)
			} else if ipNet, ok := addr.(*net.IPNet); ok {
				// TODO: Remove assumption that the host IP is the first IP in the
				// network.
				ip := ipNet.IP.Mask(ipNet.Mask)
				nextIP(ip)
				hostIPs = append(hostIPs, ip)
			} else {
				fmt.Printf("Ignoring host address of unknown type: %v\n", addr)
			}
		}
	}
	return hostIPs, nil
}

func nextIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
