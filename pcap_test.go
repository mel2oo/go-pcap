package gopcap

import (
	"context"
	"testing"
)

func TestParse(t *testing.T) {
	Parse(context.TODO(), NewPcapFile("testdata/79c29c05-a337-414f-b6f7-7f7ba2089042.pcap"))
}
