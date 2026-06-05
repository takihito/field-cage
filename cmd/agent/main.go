package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/takihito/field-cage/internal/ebpf"
	"github.com/takihito/field-cage/internal/policy"
)

var (
	configPath = flag.String("config", "", "path to YAML policy file (omit to allow all)")
	mode       = flag.String("mode", "", "enforcement mode: audit or block (overrides policy file)")
)

func main() {
	flag.Parse()

	var engine *policy.Engine
	if *configPath != "" {
		var err error
		engine, err = policy.LoadFile(*configPath)
		if err != nil {
			log.Fatalf("field-cage: load policy: %v", err)
		}
	}

	// --mode flag overrides the mode in the policy file.
	effectiveMode := policy.ModeAudit
	if engine != nil {
		effectiveMode = engine.Mode()
	}
	if *mode != "" {
		effectiveMode = policy.Mode(*mode)
		switch effectiveMode {
		case policy.ModeAudit, policy.ModeBlock:
		default:
			log.Fatalf("field-cage: invalid --mode %q: must be \"audit\" or \"block\"", *mode)
		}
	}

	var watcher *ebpf.Watcher
	var err error
	if effectiveMode == policy.ModeBlock {
		watcher, err = ebpf.NewBlockWatcher("/sys/fs/cgroup")
	} else {
		watcher, err = ebpf.NewWatcher()
	}
	if err != nil {
		log.Fatalf("field-cage: failed to start: %v", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			log.Printf("field-cage: close error: %v", err)
		}
	}()

	modeLabel := string(effectiveMode)
	if engine == nil {
		modeLabel = string(effectiveMode) + " (no policy)"
	}
	fmt.Fprintf(os.Stderr, "field-cage: watching outbound connections [mode=%s] (Ctrl+C to stop)\n", modeLabel)
	if effectiveMode == policy.ModeBlock {
		// NOTE: enforcement is reactive. The cgroup/connect4 program only blocks
		// IPs that have already been seen and denied via the tracepoint stream.
		// The first outbound connection to a newly-observed disallowed IP will
		// pass through before the BPF map is updated. A future milestone will
		// invert this to a default-deny allowlist model to close the gap.
		log.Printf("field-cage: block mode active (note: first connection to each new denied IP passes through before map is updated)")
	}

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

			verdict := "ALLOW"
			if engine != nil && !engine.Allow(ev.Domain, net.IP(ev.DAddr)) {
				verdict = "DENY"
				if effectiveMode == policy.ModeBlock {
					// Use the incremental AddBlockedIP to avoid O(n) map rebuild
					// on every new denial. The BPF map cap is 4096 entries.
					if err := watcher.AddBlockedIP(ev.DAddr); err != nil {
						log.Printf("field-cage: add blocked IP: %v", err)
					}
				}
			}

			fmt.Printf("verdict=%-5s pid=%-6d tgid=%-6d comm=%-16s dst=%s:%d\n",
				verdict, ev.PID, ev.TGID, ev.Comm, dst, ev.DPort)
		}
	}()

	select {
	case <-sig:
		fmt.Fprintln(os.Stderr, "\nfield-cage: shutting down")
	case err := <-readErr:
		log.Fatalf("field-cage: reader error: %v", err)
	}
}
