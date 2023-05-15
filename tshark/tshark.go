package tshark

import (
	"crypto/x509"
	"os/exec"
	"strings"
	"sync/atomic"
)

type Certificate struct {
	ServerName  string
	Certificate *x509.Certificate
}

// tshark -nr testdata/tls.pcap -2R "tls.handshake.type == 1 || tls.handshake.certificate"  -Tfields -e tls.handshake.extensions_server_name -e tls.handshake.certificate
func ExportCertificate(exe, pcapfile string) ([]Certificate, error) {
	var err error
	if exe, err = exec.LookPath(exe); err != nil {
		return nil, err
	}

	cmd := exec.Command(exe, "-nr", pcapfile, "-2R", "\"tls.handshake.type == 1 || tls.handshake.certificate\"", "-Tfields", "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.certificate")

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	res := make([]Certificate, 0)
	iterator := NewLineIterator(string(out))
	for iterator.HasNext() {
		host, _ := iterator.Get()
		if host == "" {
			continue
		}
		if !strings.HasPrefix(host, "\t") {
			host = strings.TrimSpace(host)
		} else {
			continue
		}

		line, _ := iterator.Next()
		if !strings.HasPrefix(line, "\t") {
			continue
		}

		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) != 2 {
			continue
		}
		cert, err := x509.ParseCertificate([]byte(fields[0]))
		if err != nil {
			continue
		}

		res = append(res, Certificate{
			ServerName:  host,
			Certificate: cert,
		})
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
