package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/takihito/field-cage/internal/ebpf"
)

func main() {
	watcher, err := ebpf.NewWatcher()
	if err != nil {
		log.Fatalf("field-cage: failed to start: %v", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			log.Printf("field-cage: close error: %v", err)
		}
	}()

	fmt.Fprintln(os.Stderr, "field-cage: watching outbound connections (Ctrl+C to stop)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	readErr := make(chan error, 1)
	go func() {
		for {
			ev, err := watcher.Read()
			if err != nil {
				readErr <- err
				return
			}
			dst := ev.DAddr.String()
			if ev.Domain != "" {
				dst = fmt.Sprintf("%s (%s)", ev.Domain, ev.DAddr)
			}
			fmt.Printf("pid=%-6d tgid=%-6d comm=%-16s dst=%s:%d\n",
				ev.PID, ev.TGID, ev.Comm, dst, ev.DPort)
		}
	}()

	select {
	case <-sig:
		fmt.Fprintln(os.Stderr, "\nfield-cage: shutting down")
	case err := <-readErr:
		log.Fatalf("field-cage: reader error: %v", err)
	}
}
