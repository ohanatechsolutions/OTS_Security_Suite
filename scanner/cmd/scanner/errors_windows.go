//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func showErrorDialog(message string) {
	proc := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	title, _ := syscall.UTF16PtrFromString("Ohana Tech Solutions — GitHub Malware Scanner")
	body, _ := syscall.UTF16PtrFromString(message)
	proc.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
}
