package ftp

import (
	"bytes"
	"errors"

	"github.com/google/uuid"
	"github.com/mel2oo/go-pcap/gnet"
	"github.com/mel2oo/go-pcap/memview"
)

func newFtpRequestParser(bidiID uuid.UUID) *ftpRequestParser {
	return &ftpRequestParser{
		connectionID: bidiID,
	}
}
func newFtpResponseParser(bidiID uuid.UUID) *ftpResponseParser {
	return &ftpResponseParser{
		connectionID: bidiID,
	}
}

type ftpRequestParser struct {
	connectionID uuid.UUID
}

var _ gnet.TCPParser = (*ftpRequestParser)(nil)

func (*ftpRequestParser) Name() string {
	return "FTP Request Parser"
}

func (p *ftpRequestParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	// request cmd
	data := input.Bytes()
	i := bytes.Index(data, []byte{0x20})
	var cmd, arg string
	if i == -1 {
		cmd = getRequestArg(data)
	} else {
		cmd = string(data[:i])
		arg = getRequestArg(data[i+1:])
	}
	result = gnet.FTPRequest{
		ConnectionID: p.connectionID,
		CMD:          cmd,
		Arg:          arg,
	}
	return
}

type ftpResponseParser struct {
	connectionID uuid.UUID
}

var _ gnet.TCPParser = (*ftpRequestParser)(nil)

func (*ftpResponseParser) Name() string {
	return "FTP Response Parser"
}

func (p *ftpResponseParser) Parse(input memview.MemView, isEnd bool) (result gnet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	// request cmd
	data := input.Bytes()
	i := bytes.Index(data, []byte{0x20})
	if i == -1 {
		i = bytes.Index(data, []byte{0x2d})
		if i == -1 {
			err = errors.New("incomplete FTP record for FTP Response")
			return
		}
	}
	result = gnet.FTPResponse{
		ConnectionID: p.connectionID,
		Code:         string(data[:i]),
		Arg:          getRequestArg(data[i+1:]),
	}
	return
}

func getRequestArg(data []byte) string {
	i := bytes.Index(data, []byte{0x0d, 0x0a})
	if i == -1 {
		return ""
	}
	return string(data[:i])
}
