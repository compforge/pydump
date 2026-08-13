//go:build linux && (amd64 || arm64)

package injector

import (
	"encoding/binary"
	"testing"
)

func TestDlopenArguments(t *testing.T) {
	arguments, err := dlopenArguments(0x12345678, "/tmp/pydump-agent.so")
	if err != nil {
		t.Fatal(err)
	}
	if result := binary.LittleEndian.Uint64(arguments); result != resultPending {
		t.Fatalf("result sentinel = %#x", result)
	}
	if address := binary.LittleEndian.Uint64(arguments[8:]); address != 0x12345678 {
		t.Fatalf("dlopen address = %#x", address)
	}
	if flags := binary.LittleEndian.Uint32(arguments[16:]); flags != rtldNow {
		t.Fatalf("dlopen flags = %#x", flags)
	}
	if path := string(arguments[24 : len(arguments)-1]); path != "/tmp/pydump-agent.so" {
		t.Fatalf("Agent path = %q", path)
	}
}

func TestScheduleArguments(t *testing.T) {
	arguments, err := scheduleArguments(0x12345678, 0x1000, "/tmp/collector.sock", "0123")
	if err != nil {
		t.Fatal(err)
	}
	if address := binary.LittleEndian.Uint64(arguments[8:]); address != 0x12345678 {
		t.Fatalf("schedule address = %#x", address)
	}
	socketAddress := binary.LittleEndian.Uint64(arguments[16:])
	nonceAddress := binary.LittleEndian.Uint64(arguments[24:])
	if socketAddress != 0x1020 || nonceAddress != 0x1034 {
		t.Fatalf("argument addresses = %#x, %#x", socketAddress, nonceAddress)
	}
	if socket := string(arguments[32:51]); socket != "/tmp/collector.sock" {
		t.Fatalf("socket path = %q", socket)
	}
	if nonce := string(arguments[52:56]); nonce != "0123" {
		t.Fatalf("nonce = %q", nonce)
	}
}
