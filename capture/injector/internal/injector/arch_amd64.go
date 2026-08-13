//go:build linux && amd64

package injector

import "syscall"

type registers = syscall.PtraceRegs

var (
	syscallStub = []byte{0x0f, 0x05, 0xcc} // syscall; int3
	callStub    = []byte{0xff, 0xd0, 0xcc} // call *%rax; int3
	// See the shared data layout documented beside dlopenShellcode's use.
	dlopenShellcode = []byte{
		0x53,             // push %rbx
		0x48, 0x89, 0xfb, // mov %rdi,%rbx
		0x8b, 0x73, 0x10, // mov 16(%rbx),%esi
		0x48, 0x8d, 0x7b, 0x18, // lea 24(%rbx),%rdi
		0xff, 0x53, 0x08, // call *8(%rbx)
		0x48, 0x89, 0x03, // mov %rax,(%rbx)
		0x5b, // pop %rbx
		0xc3, // ret
	}
	scheduleShellcode = []byte{
		0x53,             // push %rbx
		0x48, 0x89, 0xfb, // mov %rdi,%rbx
		0x48, 0x8b, 0x7b, 0x10, // mov 16(%rbx),%rdi
		0x48, 0x8b, 0x73, 0x18, // mov 24(%rbx),%rsi
		0xff, 0x53, 0x08, // call *8(%rbx)
		0x48, 0x89, 0x03, // mov %rax,(%rbx)
		0x5b, // pop %rbx
		0xc3, // ret
	}
)

func getRegisters(pid int, regs *registers) error {
	return syscall.PtraceGetRegs(pid, regs)
}

func setRegisters(pid int, regs *registers) error {
	return syscall.PtraceSetRegs(pid, regs)
}

func prepareSyscall(regs *registers, code, number uintptr, arguments []uintptr) {
	regs.Rip = uint64(code)
	regs.Rax = uint64(number)
	values := argumentValues(arguments)
	regs.Rdi = values[0]
	regs.Rsi = values[1]
	regs.Rdx = values[2]
	regs.R10 = values[3]
	regs.R8 = values[4]
	regs.R9 = values[5]
}

func prepareCall(regs *registers, code, stackTop, address uintptr, arguments []uintptr) {
	regs.Rip = uint64(code)
	regs.Rax = uint64(address)
	regs.Rsp = uint64(stackTop &^ uintptr(15))
	regs.Rbp = regs.Rsp
	values := argumentValues(arguments)
	regs.Rdi = values[0]
	regs.Rsi = values[1]
	regs.Rdx = values[2]
	regs.Rcx = values[3]
	regs.R8 = values[4]
	regs.R9 = values[5]
}

func registerResult(regs *registers) uintptr {
	return uintptr(regs.Rax)
}

func argumentValues(arguments []uintptr) [6]uint64 {
	values := [6]uint64{}
	for index, value := range arguments {
		if index == len(values) {
			break
		}
		values[index] = uint64(value)
	}
	return values
}
