//go:build darwin || freebsd || linux
// +build darwin freebsd linux

package main

import "os"

func isAdmin() bool {
	return os.Getuid() == 0
}
