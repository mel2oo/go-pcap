package gnet

type TLSVersion string

const (
	TLS_v1_2 TLSVersion = "1.2"
	TLS_v1_3 TLSVersion = "1.3"
)

type TLSHandshakeVersion uint16

func (v TLSHandshakeVersion) String() string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	default:
		return "unknown"
	}
}
