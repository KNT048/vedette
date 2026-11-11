package main

import (
	"errors"
	"net"
	"os"
)

// unixDatagram is the network of a systemd notification: a client sends one datagram, nothing
// listens. It is a reviewed exception of the network-literal guard in modules/host (FORBID-2).
const unixDatagram = "unixgram"

// sdNotify tells systemd the host is ready (Type=notify, D-102 (1)): one datagram "READY=1" to the
// socket named by NOTIFY_SOCKET, which systemd sets for a Type=notify unit. The unit of the
// honeypot starts after this, so it never joins a namespace that is not ready. With no
// NOTIFY_SOCKET (run by hand) it does nothing.
func sdNotify(sock string) error {
	if sock == "" {
		return nil
	}
	if sock[0] != '/' && sock[0] != '@' {
		return errors.New("NOTIFY_SOCKET is neither a path nor an abstract socket")
	}
	if sock[0] == '@' {
		sock = "\x00" + sock[1:] // an abstract socket
	}
	c, err := net.DialUnix(unixDatagram, nil, &net.UnixAddr{Name: sock, Net: unixDatagram})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte("READY=1"))
	return err
}

// notifyReady is sdNotify("READY=1") on the real environment.
func notifyReady() error { return sdNotify(os.Getenv("NOTIFY_SOCKET")) }
