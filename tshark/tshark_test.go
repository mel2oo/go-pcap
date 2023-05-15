package tshark

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestTshark(t *testing.T) {
	code := `
`
	res := make(map[string]*x509.Certificate)
	iterator := NewLineIterator(code)
	for iterator.HasNext() {
		host, _ := iterator.Get()
		if host == "" {
			continue
		}
		if !strings.Contains(host, ".") { // 非域名
			continue
		}
		host = strings.TrimSpace(host)

		line, _ := iterator.Next()
		// 证书分隔符号
		if strings.Contains(line, ".") || !strings.Contains(line, ",") {
			continue
		}

		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) < 1 { // 兼容多个证书
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
	fmt.Println(res)
}
