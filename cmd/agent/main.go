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
	defer watcher.Close()

	fmt.Fprintln(os.Stderr, "field-cage: watching outbound connections (Ctrl+C to stop)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			ev, err := watcher.Read()
			if err != nil {
				return
			}
			fmt.Printf("pid=%-6d tgid=%-6d comm=%-16s dst=%s:%d\n",
				ev.PID, ev.TGID, ev.Comm, ev.DAddr, ev.DPort)
		}
	}()

	<-sig
	fmt.Fprintln(os.Stderr, "\nfield-cage: shutting down")
}
