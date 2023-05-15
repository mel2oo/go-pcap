package tshark

import (
	"crypto/x509"
	"encoding/hex"
	"os/exec"
	"strings"
	"sync/atomic"
)

// tshark -nr testdata/tls.pcap -2R "tls.handshake.type == 1 || tls.handshake.certificate"  -Tfields -e tls.handshake.extensions_server_name -e tls.handshake.certificate
func ExportCertificate(exe, pcapfile string) (map[string]*x509.Certificate, error) {
	var err error
	if exe, err = exec.LookPath(exe); err != nil {
		return nil, err
	}

	cmd := exec.Command(exe, "-nr", pcapfile, "-2R", "\"tls.handshake.type == 1 || tls.handshake.certificate\"", "-Tfields", "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.certificate")

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	res := make(map[string]*x509.Certificate)
	iterator := NewLineIterator(string(out))
	for iterator.HasNext() {
		host, _ := iterator.Get()
		if host == "" {
			continue
		}
		if strings.Contains(host, ",") {
			continue
		}
		host = strings.TrimSpace(host)

		line, _ := iterator.Next()
		if !strings.Contains(line, ",") {
			continue
		}

		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) != 2 {
			continue
		}
		data, err := hex.DecodeString(fields[0])
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			continue
		}

		_, ok := res[host]
		if !ok {
			res[host] = cert
		}
	}

	return res, nil
}

type LineIterator struct {
	i     int64
	lines []string
}

func NewLineIterator(lines string) *LineIterator {
	return &LineIterator{
		i:     0,
		lines: strings.Split(lines, "\n"),
	}
}

func (l *LineIterator) HasNext() bool {
	return l.i < int64(len(l.lines))
}

func (l *LineIterator) Next() (string, bool) {
	if l.HasNext() {
		line := l.lines[l.i]
		return line, true
	}
	return "", false
}

func (l *LineIterator) Get() (string, bool) {
	if l.HasNext() {
		line := l.lines[l.i]
		atomic.AddInt64(&l.i, 1)
		return line, true
	}
	return "", false
}
