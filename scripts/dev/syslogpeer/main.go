// Command syslogpeer is the two halves of `make syslog-ports-check` (scripts/dev/syslog-ports-check.sh): a listener that prints the
// address every UDP datagram and TCP connection came from, and a sender that sends one syslog line. It exists so the check can show, by
// effect, which sender address a published port delivers to the process inside the container. Dev tool only, never shipped.
//
//	syslogpeer listen <port>          prints "udp <addr>" / "tcp <addr>" for each message, flushed
//	syslogpeer send <udp|tcp> <host:port>
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: syslogpeer listen <port> | send <udp|tcp> <host:port>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "listen":
		listen(os.Args[2])
	case "send":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		c, err := net.DialTimeout(os.Args[2], os.Args[3], 5*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_, err = c.Write([]byte("<14>1 2026-11-11T00:00:00Z syslogpeer check - - - hello\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		time.Sleep(200 * time.Millisecond)
		_ = c.Close()
	default:
		os.Exit(2)
	}
}

func listen(port string) {
	pc, err := net.ListenPacket("udp4", ":"+port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp4", ":"+port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
