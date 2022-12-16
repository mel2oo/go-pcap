package pcap

import (
	"time"
)

type clockWrapper interface {
	Now() time.Time
}

type realClock struct{}

func (*realClock) Now() time.Time {
	return time.Now()
}
