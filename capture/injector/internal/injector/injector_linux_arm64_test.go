//go:build linux && arm64

package injector

import (
	"syscall"
	"testing"
)

func TestPrepareSyscallUsesX8AndX0ThroughX5(t *testing.T) {
	var registers syscall.PtraceRegs
	prepareSyscall(&registers, 10, 20, []uintptr{1, 2, 3, 4, 5, 6})
	if registers.Pc != 10 || registers.Regs[8] != 20 {
		t.Fatal("syscall PC or number is incorrect")
	}
	for index := range 6 {
		if registers.Regs[index] != uint64(index+1) {
			t.Fatalf("argument x%d = %d", index, registers.Regs[index])
		}
	}
}

func TestPrepareCallUsesX16AndAlignedStack(t *testing.T) {
	var registers syscall.PtraceRegs
	prepareCall(&registers, 10, 35, 20, []uintptr{1, 2})
	if registers.Pc != 10 || registers.Regs[16] != 20 {
		t.Fatal("call PC or function address is incorrect")
	}
	if registers.Sp != 32 || registers.Regs[29] != 32 {
		t.Fatal("call stack is not 16-byte aligned")
	}
}
