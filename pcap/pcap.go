package pcap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
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
					fmt.Printf("%d flushed, %d closed\n", flushed, closed)
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
			fmt.Println("packet handling", err)
		}
	}()

	if packet.NetworkLayer() == nil {
		return
	}

	// Use timestamp current or use the more precise timestamp on the packet, if available.
	observationTime := time.Now()
	if packet.Metadata() != nil {
		if t := packet.Metadata().Timestamp; !t.IsZero() {
			observationTime = t
		}
	}

	// packet layer class
	types := make([]gopacket.LayerType, 0)
	for _, layer := range packet.Layers() {
		types = append(types, layer.LayerType())
	}
	class := gopacket.NewLayerClass(types)

	// Get network layer type, src and dst address
	var srcIP, dstIP net.IP
	switch l := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		srcIP = l.SrcIP
		dstIP = l.DstIP
	case *layers.IPv6:
		srcIP = l.SrcIP
		dstIP = l.DstIP
	}

	transportLayer := packet.TransportLayer()

	if transportLayer == nil {
		p.outchan <- gnet.NetTraffic{
			LayerClass: class,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			Content: gnet.BodyBytes{
				MemView: memview.New(packet.NetworkLayer().LayerPayload()),
			},

			ObservationTime: observationTime,
		}
		return
	}

	var srcPort, dstPort int
	switch t := transportLayer.(type) {
	case *layers.TCP:
		// Let TCP reassembler do extra magic to parse out higher layer protocols.
		assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), t,
			contextFromTCPPacket(packet, t))
		return
	case *layers.UDP:
		srcPort = int(t.SrcPort)
		dstPort = int(t.DstPort)
	default:
		p.outchan <- gnet.NetTraffic{
			LayerClass: class,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			Content: gnet.BodyBytes{
				MemView: memview.New(t.LayerPayload()),
			},
			ObservationTime: observationTime,
		}
		return
	}

	applicationLayer := packet.ApplicationLayer()

	switch t := applicationLayer.(type) {
	case *layers.DNS:
		p.outchan <- gnet.NetTraffic{
			LayerClass: class,
			SrcIP:      srcIP,
			SrcPort:    srcPort,
			DstIP:      dstIP,
			DstPort:    dstPort,
			Content: gnet.DNSRequest{
				ID:     t.ID,
				QR:     t.QR,
				OpCode: t.OpCode,

				AA: t.AA,
				TC: t.TC,
				RD: t.RD,
				RA: t.RA,
				Z:  t.Z,

				ResponseCode: t.ResponseCode,
				QDCount:      t.QDCount,
				ANCount:      t.ANCount,
				NSCount:      t.NSCount,
				ARCount:      t.ARCount,

				Questions:   t.Questions,
				Answers:     t.Answers,
				Authorities: t.Authorities,
				Additionals: t.Additionals,
			},
			ObservationTime: observationTime,
		}
	default:
		p.outchan <- gnet.NetTraffic{
			LayerClass: gopacket.NewLayerClass(types),
			SrcIP:      srcIP,
			SrcPort:    srcPort,
			DstIP:      dstIP,
			DstPort:    dstPort,
			Content: gnet.BodyBytes{
				MemView: memview.New(packet.NetworkLayer().LayerPayload()),
			},
			ObservationTime: observationTime,
		}
	}
}

func (p *TrafficParser) NetLayerToTraffic() {

}
