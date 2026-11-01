//go:build !linux

package main

func socketPeerPID(string) int { return 0 }
