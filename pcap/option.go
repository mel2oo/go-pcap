package pcap

const (
	DefaultStreamFlushTimeout int64 = 10
	DefaultStreamCloseTimeout int64 = 90

	DefaultMaxBufferedPagesTotal         int = 100000
	DefaultMaxBufferedPagesPerConnection int = 4000
)

type Options struct {
	// live or offline
	Live bool
	// read from offline file or live device
	ReadName string
	// bpf filter
	BPFilter string

	// The maximum time we will wait before flushing a connection and delivering
	// the data even if there is a gap in the collected sequence.
	// Default 10 seconds.
	StreamFlushTimeout int64

	// The maximum time we will leave a connection open waiting for traffic.
	// Default 90 seconds
	StreamCloseTimeout int64

	// Maximum size of gopacket reassembly buffers, per interface and direction.
	//
	// A gopacket page is 1900 bytes.
	// We want to cap the total memory usage at about 200MB = 105263 pages
	MaxBufferedPagesTotal int

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
	MaxBufferedPagesPerConnection int
}

func NewOptions() Options {
	return Options{
		StreamFlushTimeout:            DefaultStreamFlushTimeout,
		StreamCloseTimeout:            DefaultStreamCloseTimeout,
		MaxBufferedPagesTotal:         DefaultMaxBufferedPagesTotal,
		MaxBufferedPagesPerConnection: DefaultMaxBufferedPagesPerConnection,
	}
}

type Option func(*Options)

func WithReadName(name string, live bool) Option {
	return func(o *Options) {
		o.Live = live
		o.ReadName = name
	}
}

func WithBPF(filter string) Option {
	return func(o *Options) {
		o.BPFilter = filter
	}
}

func WithStreamFlushTimeout(t int64) Option {
	return func(o *Options) {
		o.StreamFlushTimeout = t
	}
}

func WithStreamCloseTimeout(t int64) Option {
	return func(o *Options) {
		o.StreamCloseTimeout = t
	}
}

func WithTotalPagesBlock(n int) Option {
	return func(o *Options) {
		o.MaxBufferedPagesTotal = n * DefaultMaxBufferedPagesTotal
	}
}

func WithPerPagesBlock(n int) Option {
	return func(o *Options) {
		o.MaxBufferedPagesPerConnection = n * DefaultMaxBufferedPagesPerConnection
	}
}
