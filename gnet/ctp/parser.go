package ctp

import (
	"bytes"
	"errors"

	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func newCtpRequestParser(bidiID uuid.UUID) *ctpRequestParser {
	return &ctpRequestParser{
		connectionID: bidiID,
	}
}
func newCtpResponseParser(bidiID uuid.UUID) *ctpResponseParser {
	return &ctpResponseParser{
		connectionID: bidiID,
	}
}

type ctpRequestParser struct {
	connectionID uuid.UUID
}

var _ gnet.TCPParser = (*ctpRequestParser)(nil)

func (*ctpRequestParser) Name() string {
	return "FTP/SMTP Request Parser"
}

func (p *ctpRequestParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	// request cmd
	data := input.Bytes()
	i := bytes.Index(data, []byte{0x20})
	var cmd, arg string
	if i == -1 {
		cmd = string(getRequestArg(data))
	} else {
		cmd = string(data[:i])
		arg = string(getRequestArg(data[i+1:]))
	}
	if cmd == "" {
		return
	}
	result = gnet.FtpSmtpRequest{
		ConnectionID: p.connectionID,
		CMD:          cmd,
		Arg:          arg,
	}
	return
}

type ctpResponseParser struct {
	connectionID uuid.UUID
}

var _ gnet.TCPParser = (*ctpRequestParser)(nil)

func (*ctpResponseParser) Name() string {
	return "FTP/SMTP Response Parser"
}

func (p *ctpResponseParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	// request cmd
	data := input.Bytes()
	i := bytes.Index(data, []byte{0x20})
	if i == -1 {
		i = bytes.Index(data, []byte{0x2d})
		if i == -1 {
			err = errors.New("incomplete FTP/SMTP record for FTP/SMTP Response")
			return
		}
	}
	result = gnet.FtpSmtpResponse{
		ConnectionID: p.connectionID,
		Code:         string(data[:i]),
		Arg:          string(getRequestArg(data[i+1:])),
	}
	return
}

func getRequestArg(data []byte) []byte {
	i := bytes.Index(data, []byte{0x0d, 0x0a})
	if i == -1 {
		return nil
	}
	return data[:i]
}
