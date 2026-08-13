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
