//go:build linux && (amd64 || arm64)

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/compforge/pydump/capture/loader/injector/internal/injector"
)

func main() {
	pid := flag.Int("pid", 0, "target process ID")
	agent := flag.String("agent", "", "Agent path as seen by the target process")
	socket := flag.String("socket", "", "Collector socket path as seen by the target process")
	nonce := flag.String("nonce", "", "32-character session nonce")
	timeout := flag.Duration("timeout", 30*time.Second, "injection timeout")
	flag.Parse()

	if *pid <= 0 || *agent == "" || *socket == "" || len(*nonce) != 32 {
		flag.Usage()
		os.Exit(2)
	}
	if err := injector.Inject(injector.Options{
		PID:        *pid,
		AgentPath:  *agent,
		SocketPath: *socket,
		Nonce:      *nonce,
		Timeout:    *timeout,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "pydump-loader: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PYDUMP_AGENT_STARTED=0")
}
