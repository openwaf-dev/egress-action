//go:build linux

package main

import (
	"net"
	"syscall"
	"time"
)

// socketPeerPID returns the pid of the process serving a unix socket (0 when unknown, or outside this pid namespace).
func socketPeerPID(path string) int {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return 0
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	_ = raw.Control(func(fd uintptr) {
		if u, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			pid = int(u.Pid)
		}
	})
	return pid
}
