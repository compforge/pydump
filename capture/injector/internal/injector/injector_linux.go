//go:build linux && (amd64 || arm64)

package injector

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	pageSize      = uintptr(4096)
	stackSize     = uintptr(2 << 20)
	bootstrapSize = 2*pageSize + stackSize
	cloneVM       = uintptr(0x100)
	rtldNow       = uint32(2)
	resultPending = ^uint64(0)
	protRead      = uintptr(1)
	protWrite     = uintptr(2)
	protExec      = uintptr(4)
	mapPrivate    = uintptr(2)
	mapAnonymous  = uintptr(0x20)
)

type Options struct {
	PID        int
	AgentPath  string
	SocketPath string
	Nonce      string
	Timeout    time.Duration
}

type mapping struct {
	start  uintptr
	offset uint64
	path   string
}

type remoteSymbol struct {
	address uintptr
	entry   uintptr
}

type tracee struct {
	pid      int
	code     uintptr
	stackTop uintptr
	regs     registers
	attached bool
}

func Inject(options Options) (result error) {
	if options.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	maps, err := readMappings(options.PID)
	if err != nil {
		return err
	}
	dlopen, err := findSymbol(options.PID, maps, []string{"dlopen", "__libc_dlopen_mode"})
	if err != nil {
		return fmt.Errorf("resolve dlopen: %w", err)
	}
	clone, err := findSymbol(options.PID, maps, []string{"clone", "__clone"})
	if err != nil {
		return fmt.Errorf("resolve clone: %w", err)
	}

	target := &tracee{pid: options.PID, code: dlopen.entry}
	if err := target.attach(); err != nil {
		return err
	}
	defer func() {
		if err := target.detach(); result == nil && err != nil {
			result = err
		}
	}()

	base, err := target.mmap(bootstrapSize)
	if err != nil {
		return fmt.Errorf("allocate bootstrap memory: %w", err)
	}
	bootstrapInUse := false
	defer func() {
		if bootstrapInUse {
			return
		}
		if err := target.munmap(base, bootstrapSize); result == nil && err != nil {
			result = fmt.Errorf("release bootstrap memory: %w", err)
		}
	}()
	dataAddress := base
	codeAddress := base + pageSize
	target.stackTop = base + bootstrapSize

	if err := target.mprotect(codeAddress, pageSize, protRead|protExec); err != nil {
		return fmt.Errorf("protect bootstrap code: %w", err)
	}
	// The clone child receives one data page containing result, dlopen address,
	// flags, padding, and the absolute Agent path. It stores the handle before
	// returning through glibc's clone wrapper.
	arguments, err := dlopenArguments(dlopen.address, options.AgentPath)
	if err != nil {
		return err
	}
	if err := target.write(dataAddress, arguments); err != nil {
		return fmt.Errorf("write dlopen arguments: %w", err)
	}
	if err := target.write(codeAddress, dlopenShellcode); err != nil {
		return fmt.Errorf("write dlopen bootstrap: %w", err)
	}
	childStack := (target.stackTop - pageSize) &^ uintptr(15)
	// Once clone starts, unmapping its code or stack is unsafe until the child
	// has stored a final dlopen result. On an indeterminate timeout we prefer a
	// bounded target-side mapping leak to crashing the process under diagnosis.
	bootstrapInUse = true
	child, err := target.call(clone.address, codeAddress, childStack, cloneVM, dataAddress)
	if err != nil {
		return fmt.Errorf("start dlopen thread: %w", err)
	}
	if int64(child) <= 0 {
		bootstrapInUse = false
		return fmt.Errorf("clone returned %d", int64(child))
	}
	handle, completed, err := target.waitForCloneResult(dataAddress, options.Timeout)
	bootstrapInUse = !completed
	if err != nil {
		return err
	}
	if handle == 0 {
		return errors.New("dlopen returned NULL")
	}

	loadedMaps, err := readMappings(options.PID)
	if err != nil {
		return err
	}
	schedule, err := findSymbolInPath(
		options.PID,
		loadedMaps,
		options.AgentPath,
		"pydump_schedule",
	)
	if err != nil {
		return fmt.Errorf("resolve pydump_schedule: %w", err)
	}
	scheduleData, err := scheduleArguments(
		schedule.address,
		dataAddress,
		options.SocketPath,
		options.Nonce,
	)
	if err != nil {
		return err
	}
	if err := target.write(dataAddress, scheduleData); err != nil {
		return fmt.Errorf("write schedule arguments: %w", err)
	}
	if err := target.write(codeAddress, scheduleShellcode); err != nil {
		return fmt.Errorf("write schedule bootstrap: %w", err)
	}
	bootstrapInUse = true
	child, err = target.call(clone.address, codeAddress, childStack, cloneVM, dataAddress)
	if err != nil {
		return fmt.Errorf("start schedule thread: %w", err)
	}
	if int64(child) <= 0 {
		bootstrapInUse = false
		return fmt.Errorf("schedule clone returned %d", int64(child))
	}
	status, completed, err := target.waitForCloneResult(dataAddress, options.Timeout)
	bootstrapInUse = !completed
	if err != nil {
		return fmt.Errorf("wait for Agent schedule: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("pydump_schedule returned %d", status)
	}
	return nil
}

func (target *tracee) attach() (result error) {
	if err := syscall.PtraceAttach(target.pid); err != nil {
		return fmt.Errorf("attach PID %d: %w", target.pid, err)
	}
	target.attached = true
	defer func() {
		if result != nil {
			result = errors.Join(result, target.detach())
		}
	}()
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(target.pid, &status, 0, nil); err != nil {
		return fmt.Errorf("wait for PID %d attach: %w", target.pid, err)
	}
	if !status.Stopped() {
		return fmt.Errorf("PID %d did not stop after attach: %#x", target.pid, uint32(status))
	}
	if err := getRegisters(target.pid, &target.regs); err != nil {
		return fmt.Errorf("read PID %d general registers: %w", target.pid, err)
	}
	return nil
}

func (target *tracee) detach() error {
	if !target.attached {
		return nil
	}
	if err := syscall.PtraceDetach(target.pid); err != nil {
		return fmt.Errorf("detach PID %d: %w", target.pid, err)
	}
	target.attached = false
	return nil
}

func (target *tracee) mmap(length uintptr) (uintptr, error) {
	result, err := target.remoteSyscall(
		syscall.SYS_MMAP,
		0,
		length,
		protRead|protWrite,
		mapPrivate|mapAnonymous,
		^uintptr(0),
		0,
	)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func (target *tracee) mprotect(address, length, protection uintptr) error {
	result, err := target.remoteSyscall(syscall.SYS_MPROTECT, address, length, protection)
	if err != nil {
		return err
	}
	if result != 0 {
		return fmt.Errorf("mprotect returned %d", result)
	}
	return nil
}

func (target *tracee) munmap(address, length uintptr) error {
	result, err := target.remoteSyscall(syscall.SYS_MUNMAP, address, length)
	if err != nil {
		return err
	}
	if result != 0 {
		return fmt.Errorf("munmap returned %d", result)
	}
	return nil
}

func (target *tracee) remoteSyscall(number uintptr, arguments ...uintptr) (uintptr, error) {
	regs := target.regs
	prepareSyscall(&regs, target.code, number, arguments)
	result, err := target.execute(&regs, syscallStub)
	if err != nil {
		return 0, err
	}
	signed := int64(result)
	if signed < 0 && signed >= -4095 {
		return 0, syscall.Errno(-signed)
	}
	return result, nil
}

func (target *tracee) call(address uintptr, arguments ...uintptr) (uintptr, error) {
	regs := target.regs
	prepareCall(&regs, target.code, target.stackTop, address, arguments)
	return target.execute(&regs, callStub)
}

func (target *tracee) execute(regs *registers, code []byte) (result uintptr, err error) {
	backup := make([]byte, len(code))
	if _, err := syscall.PtracePeekText(target.pid, target.code, backup); err != nil {
		return 0, fmt.Errorf("read bootstrap instruction: %w", err)
	}
	restoreCode := false
	defer func() {
		if restoreCode {
			if _, restoreErr := syscall.PtracePokeText(target.pid, target.code, backup); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore bootstrap instruction: %w", restoreErr))
			}
		}
		if restoreErr := setRegisters(target.pid, &target.regs); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore general registers: %w", restoreErr))
		}
	}()
	if _, err := syscall.PtracePokeText(target.pid, target.code, code); err != nil {
		return 0, fmt.Errorf("write bootstrap instruction: %w", err)
	}
	restoreCode = true
	if err := setRegisters(target.pid, regs); err != nil {
		return 0, fmt.Errorf("set general registers: %w", err)
	}
	if err := syscall.PtraceCont(target.pid, 0); err != nil {
		return 0, fmt.Errorf("continue PID %d: %w", target.pid, err)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(target.pid, &status, 0, nil); err != nil {
		return 0, fmt.Errorf("wait for remote operation: %w", err)
	}
	if !status.Stopped() || status.StopSignal() != syscall.SIGTRAP {
		return 0, fmt.Errorf("remote operation stopped unexpectedly: %#x", uint32(status))
	}
	var completed registers
	if err := getRegisters(target.pid, &completed); err != nil {
		return 0, fmt.Errorf("read remote result: %w", err)
	}
	return registerResult(&completed), nil
}

func (target *tracee) write(address uintptr, data []byte) error {
	for len(data) > 0 {
		length := len(data)
		if length > 8 {
			length = 8
		}
		chunk := data[:length]
		if length < 8 {
			word := make([]byte, 8)
			if _, err := syscall.PtracePeekData(target.pid, address, word); err != nil {
				return err
			}
			copy(word, chunk)
			chunk = word
		}
		if _, err := syscall.PtracePokeData(target.pid, address, chunk); err != nil {
			return err
		}
		address += uintptr(length)
		data = data[length:]
	}
	return nil
}

func (target *tracee) readUint64(address uintptr) (uint64, error) {
	data := make([]byte, 8)
	if _, err := syscall.PtracePeekData(target.pid, address, data); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (target *tracee) waitForCloneResult(
	address uintptr,
	timeout time.Duration,
) (uint64, bool, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result, err := target.readUint64(address)
		if err != nil {
			return 0, false, fmt.Errorf("read clone result: %w", err)
		}
		if result != resultPending {
			// The clone function stores its result immediately before returning.
			// Give glibc's wrapper time to retire the child stack before the
			// caller reuses or unmaps the bounded bootstrap region.
			time.Sleep(10 * time.Millisecond)
			return result, true, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, false, fmt.Errorf("clone task did not finish within %s", timeout)
}

func dlopenArguments(address uintptr, path string) ([]byte, error) {
	if len(path)+25 > int(pageSize) {
		return nil, errors.New("Agent path exceeds bootstrap data page")
	}
	data := make([]byte, 24+len(path)+1)
	binary.LittleEndian.PutUint64(data, resultPending)
	binary.LittleEndian.PutUint64(data[8:], uint64(address))
	binary.LittleEndian.PutUint32(data[16:], rtldNow)
	copy(data[24:], path)
	return data, nil
}

func scheduleArguments(
	address uintptr,
	dataAddress uintptr,
	socketPath string,
	nonce string,
) ([]byte, error) {
	const stringsOffset = 32
	nonceOffset := stringsOffset + len(socketPath) + 1
	if nonceOffset+len(nonce)+1 > int(pageSize) {
		return nil, errors.New("Agent arguments exceed bootstrap data page")
	}
	data := make([]byte, nonceOffset+len(nonce)+1)
	binary.LittleEndian.PutUint64(data, resultPending)
	binary.LittleEndian.PutUint64(data[8:], uint64(address))
	binary.LittleEndian.PutUint64(data[16:], uint64(dataAddress+stringsOffset))
	binary.LittleEndian.PutUint64(data[24:], uint64(dataAddress+uintptr(nonceOffset)))
	copy(data[stringsOffset:], socketPath)
	copy(data[nonceOffset:], nonce)
	return data, nil
}

func readMappings(pid int) ([]mapping, error) {
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("read PID %d mappings: %w", pid, err)
	}
	var result []mapping
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(bounds[0], 16, 64)
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		if startErr != nil || offsetErr != nil {
			continue
		}
		path := strings.Join(fields[5:], " ")
		path = strings.TrimSuffix(path, " (deleted)")
		result = append(result, mapping{start: uintptr(start), offset: offset, path: path})
	}
	return result, nil
}

func findSymbol(pid int, maps []mapping, names []string) (remoteSymbol, error) {
	paths := uniquePaths(maps)
	for _, preferred := range []string{"libc.so", "libdl.so"} {
		for _, path := range paths {
			if !strings.Contains(filepath.Base(path), preferred) {
				continue
			}
			if symbol, ok := symbolFromModule(pid, maps, path, names); ok {
				return symbol, nil
			}
		}
	}
	return remoteSymbol{}, fmt.Errorf("none of %s found in loaded libc/libdl", strings.Join(names, ", "))
}

func findSymbolInPath(pid int, maps []mapping, path, name string) (remoteSymbol, error) {
	cleanPath := strings.TrimSuffix(path, " (deleted)")
	for _, mapped := range uniquePaths(maps) {
		if mapped != cleanPath && filepath.Clean(mapped) != filepath.Clean(cleanPath) {
			continue
		}
		if symbol, ok := symbolFromModule(pid, maps, mapped, []string{name}); ok {
			return symbol, nil
		}
	}
	return remoteSymbol{}, fmt.Errorf("symbol %s not found in loaded Agent %s", name, path)
}

func symbolFromModule(pid int, maps []mapping, path string, names []string) (remoteSymbol, bool) {
	file, err := elf.Open(fmt.Sprintf("/proc/%d/root%s", pid, path))
	if err != nil {
		return remoteSymbol{}, false
	}
	defer file.Close()
	bias, ok := loadBias(file, maps, path)
	if !ok {
		return remoteSymbol{}, false
	}
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return remoteSymbol{}, false
	}
	for _, name := range names {
		for _, symbol := range symbols {
			if symbol.Name == name && symbol.Section != elf.SHN_UNDEF {
				return remoteSymbol{
					address: bias + uintptr(symbol.Value),
					entry:   bias + uintptr(file.Entry),
				}, true
			}
		}
	}
	return remoteSymbol{}, false
}

func loadBias(file *elf.File, maps []mapping, path string) (uintptr, bool) {
	for _, mapped := range maps {
		if mapped.path != path {
			continue
		}
		for _, program := range file.Progs {
			if program.Type != elf.PT_LOAD {
				continue
			}
			segmentOffset := program.Off &^ uint64(pageSize-1)
			if mapped.offset == segmentOffset {
				segmentAddress := uintptr(program.Vaddr) &^ (pageSize - 1)
				return mapped.start - segmentAddress, true
			}
		}
	}
	return 0, false
}

func uniquePaths(maps []mapping) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, mapped := range maps {
		if _, exists := seen[mapped.path]; exists {
			continue
		}
		seen[mapped.path] = struct{}{}
		result = append(result, mapped.path)
	}
	return result
}
