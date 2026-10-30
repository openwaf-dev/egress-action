//go:build linux

package main

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80 // SO_ORIGINAL_DST, linux/netfilter_ipv4.h

// originalDst returns the address a redirected (nft redirect/dnat) TCP connection was sent to.
func originalDst(c net.Conn) (*net.TCPAddr, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, errors.New("not TCP")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var sa syscall.RawSockaddrInet4
	var serr error
	err = raw.Control(func(fd uintptr) {
		l := uint32(syscall.SizeofSockaddrInet4)
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&l)), 0)
		if e != 0 {
			serr = e
		}
	})
	if err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	port := int(sa.Port>>8) | int(sa.Port&0xff)<<8
	return &net.TCPAddr{IP: net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]), Port: port}, nil
}
