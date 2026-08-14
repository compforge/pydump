//go:build linux && arm64

package injector

import "syscall"

type registers = syscall.PtraceRegs

var (
	syscallStub = []byte{
		0x01, 0x00, 0x00, 0xd4, // svc #0
		0x00, 0x00, 0x20, 0xd4, // brk #0
	}
	callStub = []byte{
		0x00, 0x02, 0x3f, 0xd6, // blr x16
		0x00, 0x00, 0x20, 0xd4, // brk #0
	}
	dlopenShellcode = []byte{
		0xf3, 0x7b, 0xbf, 0xa9, // stp x19,x30,[sp,#-16]!
		0xf3, 0x03, 0x00, 0xaa, // mov x19,x0
		0x70, 0x06, 0x40, 0xf9, // ldr x16,[x19,#8]
		0x61, 0x12, 0x40, 0xb9, // ldr w1,[x19,#16]
		0x60, 0x62, 0x00, 0x91, // add x0,x19,#24
		0x00, 0x02, 0x3f, 0xd6, // blr x16
		0x60, 0x02, 0x00, 0xf9, // str x0,[x19]
		0xf3, 0x7b, 0xc1, 0xa8, // ldp x19,x30,[sp],#16
		0xc0, 0x03, 0x5f, 0xd6, // ret
	}
	scheduleShellcode = []byte{
		0xf3, 0x7b, 0xbf, 0xa9, // stp x19,x30,[sp,#-16]!
		0xf3, 0x03, 0x00, 0xaa, // mov x19,x0
		0x70, 0x06, 0x40, 0xf9, // ldr x16,[x19,#8]
		0x60, 0x0a, 0x40, 0xf9, // ldr x0,[x19,#16]
		0x61, 0x0e, 0x40, 0xf9, // ldr x1,[x19,#24]
		0x00, 0x02, 0x3f, 0xd6, // blr x16
		0x60, 0x02, 0x00, 0xf9, // str x0,[x19]
		0xf3, 0x7b, 0xc1, 0xa8, // ldp x19,x30,[sp],#16
		0xc0, 0x03, 0x5f, 0xd6, // ret
	}
)

func resolveClone(pid int, maps []mapping) (remoteSymbol, error) {
	return findSymbol(pid, maps, []string{"clone", "__clone"})
}

func (target *tracee) startClone(
	cloneAddress uintptr,
	codeAddress uintptr,
	childStack uintptr,
	dataAddress uintptr,
	childCode []byte,
) (uintptr, error) {
	if err := target.write(codeAddress, childCode); err != nil {
		return 0, err
	}
	return target.call(cloneAddress, codeAddress, childStack, cloneVM, dataAddress)
}

func getRegisters(pid int, regs *registers) error {
	return syscall.PtraceGetRegs(pid, regs)
}

func setRegisters(pid int, regs *registers) error {
	return syscall.PtraceSetRegs(pid, regs)
}

func prepareSyscall(regs *registers, code, number uintptr, arguments []uintptr) {
	regs.Pc = uint64(code)
	regs.Regs[8] = uint64(number)
	setRegisterArguments(regs, arguments)
}

func prepareCall(regs *registers, code, stackTop, address uintptr, arguments []uintptr) {
	regs.Pc = uint64(code)
	regs.Sp = uint64(stackTop &^ uintptr(15))
	regs.Regs[29] = regs.Sp
	regs.Regs[16] = uint64(address)
	setRegisterArguments(regs, arguments)
}

func registerResult(regs *registers) uintptr {
	return uintptr(regs.Regs[0])
}

func setRegisterArguments(regs *registers, arguments []uintptr) {
	for index := range 6 {
		regs.Regs[index] = 0
	}
	for index, value := range arguments {
		if index == 6 {
			break
		}
		regs.Regs[index] = uint64(value)
	}
}
