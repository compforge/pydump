//go:build linux && amd64

package injector

import (
	"syscall"
	"testing"
)

func TestSetSyscallArgumentsUsesR10ForFourthArgument(t *testing.T) {
	var registers syscall.PtraceRegs
	prepareSyscall(&registers, 10, 20, []uintptr{1, 2, 3, 4, 5, 6})
	if registers.Rdi != 1 || registers.Rsi != 2 || registers.Rdx != 3 {
		t.Fatal("first three syscall arguments are incorrect")
	}
	if registers.R10 != 4 || registers.R8 != 5 || registers.R9 != 6 {
		t.Fatal("last three syscall arguments are incorrect")
	}
}

func TestPrepareCloneUsesRawSyscallRegistersAndSeparateStacks(t *testing.T) {
	var registers syscall.PtraceRegs
	prepareClone(&registers, 0x1000, 0x203f, 0x3000, 0x4000, 0x5000)
	if registers.Rip != 0x1000 || registers.Rax != syscall.SYS_CLONE {
		t.Fatal("clone instruction pointer or syscall number is incorrect")
	}
	if registers.Rsp != 0x2030 || registers.Rbp != 0x2030 {
		t.Fatal("parent stack is not 16-byte aligned")
	}
	if registers.Rdi != uint64(cloneVM) || registers.Rsi != 0x3000 {
		t.Fatal("clone flags or child stack is incorrect")
	}
	if registers.R12 != 0x4000 || registers.R13 != 0x5000 {
		t.Fatal("child bootstrap function or argument is incorrect")
	}
}
