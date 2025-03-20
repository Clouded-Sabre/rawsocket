//go:build darwin || freebsd || linux
// +build darwin freebsd linux

package lib

import "os"

func isAdmin() bool {
	return os.Getuid() == 0
}
