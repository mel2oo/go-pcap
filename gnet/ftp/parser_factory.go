package ftp

import (
	"bytes"

	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func NewFTPRequestParserFactory() gnet.TCPParserFactory {
	return &ftpRequestParserFactory{}
}

func NewFTPResponseParserFactory() gnet.TCPParserFactory {
	return &ftpResponseParserFactory{}
}

// ftp request
type ftpRequestParserFactory struct{}

func (*ftpRequestParserFactory) Name() string {
	return "FTP Request Parser Factory"
}

func (factory *ftpRequestParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}
	return decision, discardFront
}

var (
	// https://www.w3.org/Protocols/rfc959/4_FileTransfer.html
	// # Request
	// ## Request CMD
	// 		xxx
	// ## Request arg
	// 		xxx
	// ##结束符
	// 		/r/n (0x0d,0x0a)

	// # Response
	// ## Response Code
	// 		1xy: '1' - '5'
	// 		x2y: '0' - '5'
	// 		xy3: 0x00
	// ##分隔符 0x20
	// ## Response arg
	// 		... 		##不定长
	// ##结束符
	// 		/r/n (0x0d,0x0a)
	minFtpCMDLengthBytes int64 = 3 + 1 + 1 + 2
)

func (*ftpRequestParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < minFtpCMDLengthBytes {
		return gnet.NeedMoreData, 0
	}

	data := input.Bytes()
	i := bytes.Index(data, []byte{0x20})
	if i < 0 {
		return gnet.Reject, 0
	}
	cmd := data[:i]
	// match request cmd
	if !CheckRequestCMD(cmd) {
		return gnet.Reject, 0
	}
	// match end
	length := len(data)
	if data[length-2] != 0x0d || data[length-1] != 0x0a {
		return gnet.Reject, 0
	}

	return gnet.Accept, 0
}

func (factory *ftpRequestParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newFtpRequestParser(id)
}

// ftp response
type ftpResponseParserFactory struct{}

func (*ftpResponseParserFactory) Name() string {
	return "FTP Response Parser Factory"
}

func (factory *ftpResponseParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}
	return decision, discardFront
}

func (*ftpResponseParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < minFtpCMDLengthBytes {
		return gnet.NeedMoreData, 0
	}

	data := input.Bytes()
	// match response code
	if data[0] < 0x31 ||
		data[0] > 0x35 ||
		data[1] > 0x35 {
		return gnet.Reject, 0
	}
	if data[3] != 0x20 && data[3] != 0x2d {
		return gnet.Reject, 0
	}
	// match end
	length := len(data)
	if data[length-2] != 0x0d || data[length-1] != 0x0a {
		return gnet.Reject, 0
	}

	return gnet.Accept, 0
}

func (factory *ftpResponseParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newFtpResponseParser(id)
}
