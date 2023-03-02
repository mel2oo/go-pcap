package ctp

import (
	"bytes"

	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func NewCtpRequestParserFactory() gnet.TCPParserFactory {
	return &ctpRequestParserFactory{}
}

func NewCtpResponseParserFactory() gnet.TCPParserFactory {
	return &ctpResponseParserFactory{}
}

// ctp request
type ctpRequestParserFactory struct{}

func (*ctpRequestParserFactory) Name() string {
	return "Ftp/Smtp Request Parser Factory"
}

func (factory *ctpRequestParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}
	return decision, discardFront
}

var (
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
	minFtpCMDLengthBytes int64 = 3 + 2
)

func (*ctpRequestParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
	if input.Len() < minFtpCMDLengthBytes {
		return gnet.NeedMoreData, 0
	}

	data := input.Bytes()
	i := bytes.Index(data, []byte{0x20})
	var cmd []byte
	if i == -1 {
		cmd = getRequestArg(data)
	} else {
		cmd = data[:i]
	}
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

func (factory *ctpRequestParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newCtpRequestParser(id)
}

// ctp response
type ctpResponseParserFactory struct{}

func (*ctpResponseParserFactory) Name() string {
	return "Ftp/Smtp Response Parser Factory"
}

func (factory *ctpResponseParserFactory) Accepts(input memview.MemView, isEnd bool) (decision gnet.AcceptDecision, discardFront int64) {
	decision, discardFront = factory.accepts(input)

	if decision == gnet.NeedMoreData && isEnd {
		decision = gnet.Reject
		discardFront = input.Len()
	}
	return decision, discardFront
}

func (*ctpResponseParserFactory) accepts(input memview.MemView) (decision gnet.AcceptDecision, discardFront int64) {
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

func (factory *ctpResponseParserFactory) CreateParser(id uuid.UUID, seq, ack reassembly.Sequence) gnet.TCPParser {
	return newCtpResponseParser(id)
}

func CheckRequestCMD(b []byte) bool {
	return CheckFtpCMD(b) || CheckSmtpCMD(b)
}
