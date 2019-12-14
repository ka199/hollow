package main

import (
	"syscall"
	"unsafe"
)

type ProcessBasicInformation struct {
	Reserved1       uint
	PebBaseAddress  uint32
	Reserved2       [2]uint
	UniqueProcessId uint32
	Reserved3       uint
}

type PEB struct {
	inheritedAddressSpace    byte
	readImageFileExecOptions byte
	beingDebugged            byte
	spare                    byte
	mutant                   uint
	imageBaseAddress         uint
}

func findRemotePEB(handle syscall.Handle) uint32 {
	procBasicInfo := ProcessBasicInformation{}
	var retLength uint32
	NtQueryInformationProcess(handle, 0,
		uintptr(unsafe.Pointer(&procBasicInfo)),
		uintptr(unsafe.Sizeof(procBasicInfo)),
		uintptr(unsafe.Pointer(&retLength)))

	return procBasicInfo.PebBaseAddress
}

func readRemoteImage(handle syscall.Handle) *PEB {
	peb := PEB{}
	addr := findRemotePEB(handle)

	ReadProcessMemory(handle,
		uintptr(addr),
		uintptr(unsafe.Pointer(&peb)),
		uintptr(unsafe.Sizeof(peb)),
		0)

	return &peb
}
