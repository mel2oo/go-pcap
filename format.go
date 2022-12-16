package gopcap

type NetInfo struct {
	HTTPs       []interface{}
	Connections []interface{}
	DNSs        []interface{}
}

type Http struct {
	Timeshift string
}

type Connection struct {
	Timeshift string
	Protocol  string
}
