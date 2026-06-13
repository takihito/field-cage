package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/takihito/field-cage/internal/ebpf"
	"github.com/takihito/field-cage/internal/policy"
	"github.com/takihito/field-cage/internal/report"
)

// seedLookupTimeout bounds each startup DNS resolution so that a hung or
// misconfigured resolver cannot stall block-mode startup indefinitely.
const seedLookupTimeout = 5 * time.Second

// version is the release version, injected at build time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

var (
	configPath  = flag.String("config", "", "path to YAML policy file (omit to allow all)")
	modeFlag    = flag.String("mode", "", "enforcement mode: audit or block (overrides policy file)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("field-cage %s\n", version)
		return
	}

	if err := run(*configPath, *modeFlag); err != nil {
		log.Fatalf("field-cage: %v", err)
	}
}

// resolveMode determines the effective enforcement mode: the --mode flag
// overrides the mode from the policy file; without either, audit is the
// default. Block mode is default-deny, so it requires a policy: without an
// allowlist every outbound connection would be rejected, bricking the runner.
func resolveMode(flagMode string, engine *policy.Engine) (policy.Mode, error) {
	mode := policy.ModeAudit
	if engine != nil {
		mode = engine.Mode()
	}
	if flagMode != "" {
		mode = policy.Mode(flagMode)
		switch mode {
		case policy.ModeAudit, policy.ModeBlock:
		default:
			return "", fmt.Errorf("invalid --mode %q: must be %q or %q", flagMode, policy.ModeAudit, policy.ModeBlock)
		}
	}
	if mode == policy.ModeBlock && engine == nil {
		return "", fmt.Errorf("block mode requires a policy file (use --config); refusing to deny all traffic")
	}
	return mode, nil
}

func run(configPath, flagMode string) error {
	var engine *policy.Engine
	if configPath != "" {
		var err error
		engine, err = policy.LoadFile(configPath)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
	}

	mode, err := resolveMode(flagMode, engine)
	if err != nil {
		return err
	}

	var watcher *ebpf.Watcher
	if mode == policy.ModeBlock {
		watcher, err = ebpf.NewBlockWatcher("/sys/fs/cgroup", engine.IsAllowedDomain)
	} else {
		watcher, err = ebpf.NewWatcher()
	}
	if err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			log.Printf("field-cage: close error: %v", err)
		}
	}()

	// Seed the allowlist before announcing readiness so that connections to
	// already-resolvable allowlisted domains and explicit IPs are permitted from
	// the first attempt.
	if mode == policy.ModeBlock {
		seedAllowlist(watcher, engine)
	}

	modeLabel := string(mode)
	if engine == nil {
		modeLabel += " (no policy)"
	}
	fmt.Fprintf(os.Stderr, "field-cage %s: watching outbound connections [mode=%s] (Ctrl+C to stop)\n", version, modeLabel)
	if mode == policy.ModeBlock {
		// Enforcement is default-deny: the cgroup/connect4 program rejects any
		// outbound connection whose destination IP is not on the allowlist.
		// DNS (port 53) and loopback (127.0.0.0/8) are always permitted so name
		// resolution and local services keep working. Limitations: only IPv4 is
		// enforced (IPv6/connect6 is not yet hooked), and a connection to an
		// allowlisted domain may be denied on the very first attempt if the
		// application connects before the observed DNS response is applied to the
		// map (fail-closed; the application's retry succeeds).
		log.Printf("field-cage: block mode active (default-deny; DNS and loopback always allowed; IPv4 only)")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// A typed-nil *policy.Engine must become a nil interface so that
	// report.VerdictFor treats "no policy" as allow-all.
	var allower report.Allower
	if engine != nil {
		allower = engine
	}

	readErr := make(chan error, 1)
	go func() {
		for {
			ev, err := watcher.Read()
			if err != nil {
				readErr <- err
				return
			}

			verdict := report.VerdictFor(ev.DPort, ev.DAddr, ev.Domain, allower)
			fmt.Println(report.Line{
				Verdict:   verdict,
				PID:       ev.PID,
				TGID:      ev.TGID,
				Comm:      ev.Comm,
				Dst:       report.Dst(ev.Domain, ev.DAddr),
				DPort:     ev.DPort,
				ConnectMs: ev.ConnectMs,
			})
		}
	}()

	select {
	case <-sig:
		fmt.Fprintln(os.Stderr, "\nfield-cage: shutting down")
	case err := <-readErr:
		return fmt.Errorf("reader error: %w", err)
	}
	return nil
}

// seedAllowlist primes the enforcement map with the policy's explicit IP
// entries and the current IPv4 addresses of each allowlisted domain. This lets
// connections to already-resolvable destinations succeed on the first attempt
// rather than relying solely on observed DNS responses. Resolution failures are
// logged and skipped; the domain can still be permitted later when its DNS
// response is observed.
func seedAllowlist(w *ebpf.Watcher, engine *policy.Engine) {
	for _, ip := range engine.IPs() {
		if err := w.AllowIP(ip); err != nil {
			log.Printf("field-cage: seed allowed IP %s: %v", ip, err)
		}
	}
	var resolver net.Resolver
	for _, domain := range engine.Domains() {
		// "ip4" restricts results to IPv4; IPv6 enforcement is not yet
		// implemented. Each lookup is bounded by seedLookupTimeout so a slow or
		// unreachable resolver cannot block startup indefinitely.
		ctx, cancel := context.WithTimeout(context.Background(), seedLookupTimeout)
		ips, err := resolver.LookupIP(ctx, "ip4", domain)
		cancel()
		if err != nil {
			log.Printf("field-cage: seed: resolve %s failed (will rely on observed DNS): %v", domain, err)
			continue
		}
		for _, ip := range ips {
			if err := w.AllowIP(ip); err != nil {
				log.Printf("field-cage: seed allowed IP %s (%s): %v", ip, domain, err)
			}
		}
	}
}
