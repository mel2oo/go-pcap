package gnet

func Tee(in <-chan ParsedNetworkTraffic) (<-chan ParsedNetworkTraffic, <-chan ParsedNetworkTraffic) {
	out1 := make(chan ParsedNetworkTraffic)
	out2 := make(chan ParsedNetworkTraffic)

	go func() {
		defer close(out1)
		defer close(out2)
		for t := range in {
			out1 <- t
			out2 <- t
		}
	}()

	return out1, out2
}
