package tshark

import (
	"testing"
)

func TestXxx(t *testing.T) {
	certs, err := ExportCertificate("tshark", "../testdata/tls.pcap")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(certs)
}
