//go:build !linux

package main

import (
	"errors"
	"net"
)

func originalDst(net.Conn) (*net.TCPAddr, error) {
	return nil, errors.New("transparent mode needs Linux")
}
