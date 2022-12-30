package pcap

import (
	"context"
	"errors"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/mel2oo/go-pcap/gnet"
)

type TrafficParser struct {
	opts    Options
	reader  PcapReader
	outchan chan gnet.NetTraffic
}

func NewTrafficParser(opt ...Option) (*TrafficParser, error) {
	opts := NewOptions()
	for _, o := range opt {
		o(&opts)
	}

	if len(opts.ReadName) == 0 {
		return nil, errors.New("please set reader name")
	}

	var reader PcapReader
	if !opts.Live {
		reader = NewFileReader(opts.ReadName, opts.BPFilter)
	} else {
		reader = NewDeviceReader(opts.ReadName, opts.BPFilter)
	}

	return &TrafficParser{
		opts:    opts,
		reader:  reader,
		outchan: make(chan gnet.NetTraffic, 100),
	}, nil
}

// Parses network traffic from an interface.
// This function will attempt to parse the traffic with the highest level of
// protocol details as possible. For instance, it will try to piece together
// HTTP request and response pairs.
// The order of parsers matters: earlier parsers will get tried first. Once a
// parser has been accepted, no other parser will be used.
func (p *TrafficParser) Parse(ctx context.Context,
	fs ...gnet.TCPParserFactory) (<-chan gnet.NetTraffic, error) {
	// Read in packets, pass to assembler
	packets, err := p.reader.Capture(ctx)
	if err != nil {
		return nil, err
	}

	// Set up assembly
	streamFactory := newTCPStreamFactory(p.outchan, gnet.TCPParserFactorySelector(fs))
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	// Override the assembler configuration. (This is the documented way to change them.)
	// Give this particular assembler a fraction of the total pages; there doesn't seem to be a way
	// to set an aggregate limit without major work.
	assembler.AssemblerOptions.MaxBufferedPagesTotal = p.opts.MaxBufferedPagesTotal
	assembler.AssemblerOptions.MaxBufferedPagesPerConnection = p.opts.MaxBufferedPagesPerConnection

	streamFlushTimeout := time.Duration(p.opts.StreamFlushTimeout) * time.Second
	streamCloseTimeout := time.Duration(p.opts.StreamCloseTimeout) * time.Second

	go func() {
		ticker := time.NewTicker(streamFlushTimeout / 4)
		defer ticker.Stop()

		// Signal caller that we're done on exit
		defer close(p.outchan)

		for {
			select {
			// packets channel is going to read until EOF or when signalClose is
			// invoked.
			case packet, more := <-packets:
				if !more || packet == nil {
					// Flushes and closes all remaining connections. This should trigger all
					// parsers to hit EOF and return. This call will block until the parsers
					// have returned because tcpStream.ReassemblyComplete waits for
					// parsers.
					//
					// This is not safe to call in a defer, because it will be called on abnormal
					// exit from FlushCloseOlderThan (like a parser segfault) but assembler might
					// not be in a safe state to call (like holding a mutex.)
					assembler.FlushAll()

					return
				}

				p.PacketToNetTraffic(assembler, packet)
			case <-ticker.C:
				// The assembler stops reassembly for streams older than streamFlushTimeout.
				// This means the corresponding tcpFlow readers will return EOF.
				//
				// If there is a missing portion of the TCP reassembly (usually due to an
				// uncaptured packet) older then the stream timeout, then this call forces
				// the assembler to skip the missing data and deliver what it has accumulated
				// after that point. The stream will not be closed if it has received
				// packets more recently than that gap.
				//
				// TODO: is this maybe the source of splices, too?  Converting dropped packets
				// into a continous stream?
				//
				// Streams that are idle need to be closed eventually, too.  We use a larger
				// threshold for that because it costs us less memory to keep just a
				// connection record, rather than a backlog of data in the reassembly buffer.
				now := time.Now()
				streamFlushThreshold := now.Add(-streamFlushTimeout)
				streamCloseThreshold := now.Add(-streamCloseTimeout)
				flushed, closed := assembler.FlushWithOptions(
					reassembly.FlushOptions{
						T:  streamFlushThreshold,
						TC: streamCloseThreshold,
					})

				if flushed != 0 || closed != 0 {
					continue
				}
			}
		}
	}()

	return p.outchan, nil
}

func (p *TrafficParser) PacketToNetTraffic(assembler *reassembly.Assembler, packet gopacket.Packet) {
	defer func() {
		// If we panic during packet handling, do not crash the program. Instead log the error and backtrace.
		// We can perform selective error-handling based on the type of the object passed to panic(),
		// but we can't choose not to recover from certain errors; we would have to re-panic.
		if err := recover(); err != nil {
			return
		}
	}()

	observationTime := time.Now()
	// Use timestamp current or use the more precise timestamp on the packet, if available.
	if packet.Metadata() != nil {
		if t := packet.Metadata().Timestamp; !t.IsZero() {
			observationTime = t
		}
	}

	traffic := &gnet.NetTraffic{
		ObservationTime: observationTime,
	}

	if packet.NetworkLayer() == nil {
		return
	}

	ParseNetTraffic(assembler, packet, traffic, p.outchan)
}

func ParseNetTraffic(assembler *reassembly.Assembler, packet gopacket.Packet,
	traffic *gnet.NetTraffic, outchan chan gnet.NetTraffic) {
	switch layer := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		traffic.SrcIP = layer.SrcIP
		traffic.DstIP = layer.DstIP
	case *layers.IPv6:
		traffic.SrcIP = layer.SrcIP
		traffic.DstIP = layer.DstIP
	}

	TransLayerToTraffic(assembler, packet, traffic, outchan)
}

func TransLayerToTraffic(assembler *reassembly.Assembler, packet gopacket.Packet,
	traffic *gnet.NetTraffic, outchan chan gnet.NetTraffic) {
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		assembler.AssembleWithContext(
			packet.NetworkLayer().NetworkFlow(),
			layer,
			contextFromTCPPacket(packet, layer),
		)
		return

	case *layers.UDP:
		traffic.LayerType = packet.TransportLayer().LayerType().String()
		traffic.Payload = layer.LayerPayload()

		UdpLayerToTraffic(packet, traffic)

	default:
		traffic.Payload = packet.NetworkLayer().LayerPayload()

		if packet.Layer(layers.LayerTypeICMPv4) != nil {
			traffic.LayerType = layers.LayerTypeICMPv4.String()
		} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
			traffic.LayerType = layers.LayerTypeICMPv6.String()
		}
	}

	outchan <- *traffic
}

func UdpLayerToTraffic(packet gopacket.Packet, traffic *gnet.NetTraffic) {
	traffic.SrcPort = int(packet.TransportLayer().(*layers.UDP).SrcPort)
	traffic.DstPort = int(packet.TransportLayer().(*layers.UDP).DstPort)

	switch l := packet.ApplicationLayer().(type) {
	case *layers.DNS:
		traffic.LayerType = l.LayerType().String()
		traffic.Content = gnet.DNSRequest{
			ID:     l.ID,
			QR:     l.QR,
			OpCode: l.OpCode,

			AA: l.AA,
			TC: l.TC,
			RD: l.RD,
			RA: l.RA,
			Z:  l.Z,

			ResponseCode: l.ResponseCode,
			QDCount:      l.QDCount,
			ANCount:      l.ANCount,
			NSCount:      l.NSCount,
			ARCount:      l.ARCount,

			Questions:   l.Questions,
			Answers:     l.Answers,
			Authorities: l.Authorities,
			Additionals: l.Additionals,
		}
	}
}
