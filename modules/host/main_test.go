package host_test

import (
	"flag"
	"os"
	"runtime"
	"strconv"
	"testing"
)

// TestMain runs twice as many parallel tests as -parallel's default (GOMAXPROCS) unless the run sets -parallel itself.
// Every test here is parallel and most of their time is spent waiting for the fake binaries they fork and for fsync,
// not on a CPU: at the default the machine was half idle (measured 2026-11-12 on 4 cores, -race: 53 s at 4, 34 s at 8,
// 33 s at 16).
func TestMain(m *testing.M) {
	flag.Parse()
	set := false
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == "test.parallel" })
	if !set {
		if err := flag.Set("test.parallel", strconv.Itoa(2*runtime.GOMAXPROCS(0))); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}
