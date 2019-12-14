package main

type BaseRelocationBlock struct {
	PageAddress uint32
	BlockSize   uint32
}

func countRelocationEntries(size uint32) uint32 {
	return (size - 8) / 2
}
