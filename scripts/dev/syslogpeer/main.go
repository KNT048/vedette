// Command syslogpeer is the helper of `make syslog-ports-check` (scripts/dev/syslog-ports-check.sh): a listener that prints the address
// every UDP datagram and TCP connection came from, and a sender. It exists so the check can show, by effect, which sender address a
// published port delivers to the process inside the container. Dev tool only, never shipped.
//
//	syslogpeer listen <port>                     prints "ready", then "udp <addr>" / "tcp <addr>" for each message, flushed
//	syslogpeer send <udp|tcp> <host:port>        one syslog line
//	syslogpeer loop <host:port> <sourceport>     one UDP line a second from a FIXED source port, until killed (a device that never pauses)
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const line = "<14>1 2026-11-11T00:00:00Z syslogpeer check - - - hello\n"

func main() {
	a := os.Args
	switch {
	case len(a) == 3 && a[1] == "listen":
		listen(a[2])
	case len(a) == 4 && a[1] == "send":
		c, err := net.DialTimeout(a[2], a[3], 5*time.Second)
		die(err)
		_, err = c.Write([]byte(line))
		die(err)
		time.Sleep(200 * time.Millisecond)
		_ = c.Close()
	case len(a) == 4 && a[1] == "loop":
		sp, err := strconv.Atoi(a[3])
		die(err)
		dst, err := net.ResolveUDPAddr("udp4", a[2])
		die(err)
		c, err := net.DialUDP("udp4", &net.UDPAddr{Port: sp}, dst)
		die(err)
		for {
			_, _ = c.Write([]byte(line)) // a refused or lost datagram is the point of the test, not an error
			time.Sleep(time.Second)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: syslogpeer listen <port> | send <udp|tcp> <host:port> | loop <host:port> <sourceport>")
		os.Exit(2)
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func listen(port string) {
	pc, err := net.ListenPacket("udp4", ":"+port)
	die(err)
	ln, err := net.Listen("tcp4", ":"+port)
	die(err)
	fmt.Println("ready")
	go func() {
		buf := make([]byte, 2048)
		for {
			_, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			fmt.Println("udp", a.(*net.UDPAddr).IP)
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		fmt.Println("tcp", c.RemoteAddr().(*net.TCPAddr).IP)
		_ = c.Close()
	}
}
