//go:build linux && amd64

package injector

import (
	"fmt"
	"syscall"
)

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
	// Invoke clone as a raw syscall so injection does not depend on the target
	// glibc clone wrapper. The parent stops at int3; the child calls the supplied
	// bootstrap and exits without returning into the target application.
	cloneBootstrap = []byte{
		0xb8, 0x38, 0x00, 0x00, 0x00, // mov $SYS_clone,%eax
		0x0f, 0x05, // syscall
		0x48, 0x85, 0xc0, // test %rax,%rax
		0x74, 0x01, // jz child
		0xcc,             // int3
		0x4c, 0x89, 0xef, // child: mov %r13,%rdi
		0x41, 0xff, 0xd4, // call *%r12
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov $SYS_exit,%eax
		0x31, 0xff, // xor %edi,%edi
		0x0f, 0x05, // syscall
		0x0f, 0x0b, // ud2
	}
)

func resolveClone(_ int, _ []mapping) (remoteSymbol, error) {
	return remoteSymbol{}, nil
}

func (target *tracee) startClone(
	_ uintptr,
	codeAddress uintptr,
	childStack uintptr,
	dataAddress uintptr,
	childCode []byte,
) (uintptr, error) {
	if len(cloneBootstrap)+len(childCode) > int(pageSize) {
		return 0, fmt.Errorf("clone bootstrap exceeds one code page")
	}
	code := make([]byte, 0, len(cloneBootstrap)+len(childCode))
	code = append(code, cloneBootstrap...)
	code = append(code, childCode...)
	if err := target.write(codeAddress, code); err != nil {
		return 0, fmt.Errorf("write raw clone bootstrap: %w", err)
	}

	regs := target.regs
	prepareClone(
		&regs,
		codeAddress,
		target.stackTop,
		childStack,
		codeAddress+uintptr(len(cloneBootstrap)),
		dataAddress,
	)
	return target.executeRegisters(&regs)
}

func prepareClone(
	regs *registers,
	codeAddress uintptr,
	parentStack uintptr,
	childStack uintptr,
	childFunction uintptr,
	childArgument uintptr,
) {
	regs.Rip = uint64(codeAddress)
	regs.Rsp = uint64(parentStack &^ uintptr(15))
	regs.Rbp = regs.Rsp
	regs.Rax = uint64(syscall.SYS_CLONE)
	regs.Rdi = uint64(cloneVM)
	regs.Rsi = uint64(childStack)
	regs.Rdx = 0
	regs.R10 = 0
	regs.R8 = 0
	regs.R12 = uint64(childFunction)
	regs.R13 = uint64(childArgument)
}

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
