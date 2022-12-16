package http

import (
	"math/rand"
	"strconv"
	"strings"

	"github.com/mel2oo/go-pcap/memview"
)

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
)

func randomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Segments the input into 3 parts in all possible ways and returns the all the
// MemViews generated.
func segment3(input string) <-chan []memview.MemView {
	out := make(chan []memview.MemView)

	go func() {
		for i := 0; i < len(input); i++ {
			for j := i; j < len(input); j++ {
				mvs := []memview.MemView{}
				mvs = append(mvs, memview.New([]byte(input[:i])))
				mvs = append(mvs, memview.New([]byte(input[i:j])))
				mvs = append(mvs, memview.New([]byte(input[j:])))
				out <- mvs
			}
		}
		close(out)
	}()

	return out
}

// Segments the input into 4 parts in all possible ways and returns the all the
// MemViews generated.
func segment(input string) <-chan []memview.MemView {
	out := make(chan []memview.MemView)

	go func() {
		for i := 0; i < len(input); i++ {
			for j := i; j < len(input); j++ {
				for k := j; k < len(input); k++ {
					mvs := []memview.MemView{}
					mvs = append(mvs, memview.New([]byte(input[:i])))
					mvs = append(mvs, memview.New([]byte(input[i:j])))
					mvs = append(mvs, memview.New([]byte(input[j:k])))
					mvs = append(mvs, memview.New([]byte(input[k:])))
					out <- mvs
				}
			}
		}
		close(out)
	}()

	return out
}

func dump(mvs []memview.MemView) string {
	ret := []string{}
	for _, mv := range mvs {
		ret = append(ret, strconv.Quote(mv.String()))
	}
	return "[" + strings.Join(ret, ",") + "]"
}
