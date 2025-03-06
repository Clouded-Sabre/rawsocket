//go:build windows
// +build windows

package main

import "golang.org/x/sys/windows"

func isAdmin() bool {
	// Load shell32.dll and get IsUserAnAdmin function
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	isUserAnAdmin := shell32.NewProc("IsUserAnAdmin")

	// Call function, non-zero return value means admin privileges
	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0
}
