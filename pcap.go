package gopcap

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/reassembly"
)

// The maximum time we will wait before flushing a connection and delivering
// the data even if there is a gap in the collected sequence.
var StreamTimeoutSeconds int64 = 10

// The maximum time we will leave a connection open waiting for traffic.
// 90 seconds is the longest possible that the upper layers can wait for
// a response before the request is uploaded before it.  (But this might
// happen as soon as 60 seconds.)
var StreamCloseTimeoutSeconds int64 = 90

// Maximum size of gopacket reassembly buffers, per interface and direction.
//
// A gopacket page is 1900 bytes.
// We want to cap the total memory usage at about 200MB = 105263 pages
var MaxBufferedPagesTotal int = 100_000

// What is a reasonable worst case? We should have enough so that if the
// packet is retransmitted, we will get it before giving up.
// 10Gb/s networking * 1ms RTT = 1.25 MB = 1Gb/s networking * 10ms RTT
// We have observed 3GB growth in RSS over 40 seconds = 75MByte/s
// Assuming a very long 100ms RTT then we'd need 75MB/s * 100ms = 7.5 MB
// 7.5MB / 1900 bytes = 3947 pages
// This would permit only 37 connections to simultaneously stall;
// 1.5MB / 1900 bytes = 657 pages might be better.
// TODO: Would be interesting to know the TCP window sizes we see in practice
// and adjust that way.
var MaxBufferedPagesPerConnection int = 4_000

func Parse(ctx context.Context, reader Reader) error {
	packets, err := reader.Packets(ctx)
	if err != nil {
		return err
	}

	// set up assembly
	streamFactory := newTCPStreamFactory()
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	assembler.AssemblerOptions.MaxBufferedPagesTotal = MaxBufferedPagesTotal
	assembler.AssemblerOptions.MaxBufferedPagesPerConnection = MaxBufferedPagesPerConnection

	streamFlushTimeout := time.Duration(StreamTimeoutSeconds) * time.Second
	streamCloseTimeout := time.Duration(StreamCloseTimeoutSeconds) * time.Second

	go func() {
		ticker := time.NewTicker(streamFlushTimeout / 4)
		defer ticker.Stop()

		// Signal caller that we're done on exit
		// defer close(out)

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
				// p.observer(packet)
				// p.packetToParsedNetworkTraffic(out, assembler, packet)
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

	return nil
}

func ParseTraffic(assembler *reassembly.Assembler, packet gopacket.Packet) {

}
