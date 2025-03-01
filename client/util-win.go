//go:build windows
// +build windows

package main

import (
	"net"

	"golang.org/x/sys/windows"
)

func isAdmin() bool {
	// 加载shell32.dll并获取IsUserAnAdmin函数
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	isUserAnAdmin := shell32.NewProc("IsUserAnAdmin")

	// 调用函数，返回非零值表示有管理员权限
	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0
}

func applyFilteringRules(srcAddr, dstAddr net.IP, srcPort, dstPort int) error {
	// placeholder function
	return nil
}

func removeFilteringRules() error {
	// placeholder function
	return nil
}
