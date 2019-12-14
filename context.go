package main

const (
	CONTEXT_FULL = 0x10000b
)

type m128a struct {
	low  uint64
	high int64
}

type context struct {
	p1home               uint64
	p2home               uint64
	p3home               uint64
	p4home               uint64
	p5home               uint64
	p6home               uint64
	contextflags         uint32
	mxcsr                uint32
	segcs                uint16
	segds                uint16
	seges                uint16
	segfs                uint16
	seggs                uint16
	segss                uint16
	eflags               uint32
	dr0                  uint64
	dr1                  uint64
	dr2                  uint64
	dr3                  uint64
	dr6                  uint64
	dr7                  uint64
	rax                  uint64
	rcx                  uint64
	rdx                  uint64
	rbx                  uint64
	rsp                  uint64
	rbp                  uint64
	rsi                  uint64
	rdi                  uint64
	r8                   uint64
	r9                   uint64
	r10                  uint64
	r11                  uint64
	r12                  uint64
	r13                  uint64
	r14                  uint64
	r15                  uint64
	rip                  uint64
	anon0                [512]byte
	vectorregister       [26]m128a
	vectorcontrol        uint64
	debugcontrol         uint64
	lastbranchtorip      uint64
	lastbranchfromrip    uint64
	lastexceptiontorip   uint64
	lastexceptionfromrip uint64
}
