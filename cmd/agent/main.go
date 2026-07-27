package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/takihito/field-cage/internal/ebpf"
	"github.com/takihito/field-cage/internal/policy"
	"github.com/takihito/field-cage/internal/report"
	pkgversion "github.com/takihito/field-cage/internal/version"
)

// seedLookupTimeout bounds each startup DNS resolution so that a hung or
// misconfigured resolver cannot stall block-mode startup indefinitely.
const seedLookupTimeout = 5 * time.Second

// version is the release version. Defaults to the value tagpr maintains in
// internal/version, and can be overridden at build time via
// -ldflags "-X main.version=...".
var version = pkgversion.Version

var (
	configPath  = flag.String("config", "", "path to YAML policy file (omit to allow all)")
	modeFlag    = flag.String("mode", "", "enforcement mode: audit or block (overrides policy file)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

func main() {
	// Diagnostics go to stderr via slog; the per-connection verdict lines are
	// written separately to stdout in a stable format (see report.Line).
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	flag.Parse()

	if *showVersion {
		fmt.Printf("field-cage %s\n", version)
		return
	}

	if err := run(*configPath, *modeFlag); err != nil {
		slog.Error("agent failed", "error", err)
		os.Exit(1)
	}
}

// resolveMode determines the effective enforcement mode: the --mode flag
// overrides the mode from the policy file; a policy file may omit mode
// entirely, and without either, audit is the default. Block mode is
// default-deny, so it requires a policy: without an allowlist every outbound
// connection would be rejected, bricking the runner.
func resolveMode(flagMode string, engine *policy.Engine) (policy.Mode, error) {
	mode := policy.ModeAudit
	if engine != nil && engine.Mode() != "" {
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

	// Discover the system nameservers once and share them across the three
	// consumers — port-53 enforcement seeding, live-allowlist source
	// validation, and verdict reporting — so all agree on the same set.
	// Previously each rediscovered them independently and could disagree if
	// resolv.conf changed mid-startup. Only needed when a policy is loaded;
	// with no policy, DNS is unrestricted everywhere.
	var resolvers []net.IP
	if engine != nil {
		resolvers, err = ebpf.SystemResolvers()
		if err != nil {
			// This runs whenever a policy is loaded, so keep the message
			// mode-agnostic: in block mode only loopback DNS ends up permitted,
			// and in either mode verdict reporting falls back to allowlist
			// policy for non-loopback DNS.
			slog.Warn("discover DNS resolvers failed; only loopback DNS is "+
				"trusted and verdict reporting falls back to allowlist policy "+
				"for non-loopback DNS", "error", err)
		}
	}

	var watcher *ebpf.Watcher
	if mode == policy.ModeBlock {
		watcher, err = ebpf.NewBlockWatcher("/sys/fs/cgroup", engine.IsAllowedDomain, resolvers)
	} else {
		watcher, err = ebpf.NewWatcher()
	}
	if err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			slog.Warn("close error", "error", err)
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
	slog.Info("watching outbound connections (Ctrl+C to stop)", "version", version, "mode", modeLabel)
	if mode == policy.ModeBlock {
		// Enforcement is default-deny: the cgroup/connect4 and cgroup/connect6
		// programs reject any outbound connection whose destination IP is not on
		// the allowlist. Loopback (127.0.0.0/8 and ::1) is always permitted so
		// local services keep working. DNS (port 53) is permitted only to
		// trusted resolvers and loopback — plus allowlisted IPs like any other
		// port — unless allow_all_dns opts back into unconditional port-53
		// access. Limitation: a connection to an allowlisted domain may be
		// denied on the very first attempt if the application connects before
		// the observed DNS response is applied to the map (fail-closed; the
		// application's retry succeeds).
		dnsLabel := "restricted to trusted resolvers"
		if engine.AllowAllDNS() {
			dnsLabel = "unrestricted (allow_all_dns)"
		}
		slog.Info("block mode active (default-deny; loopback always allowed; IPv4+IPv6)", "dns", dnsLabel)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// A typed-nil *policy.Engine must become a nil interface so that
	// report.VerdictFor treats "no policy" as allow-all.
	var allower report.Allower
	if engine != nil {
		allower = engine
	}
	dnsExempt := dnsExemptFor(engine, resolvers)

	readErr := make(chan error, 1)
	go func() {
		for {
			ev, err := watcher.Read()
			if err != nil {
				readErr <- err
				return
			}

			verdict := report.VerdictFor(ev.DPort, ev.DAddr, ev.Domain, allower, dnsExempt)
			fmt.Println(report.Line{
				Verdict: verdict,
				PID:     ev.PID,
				TGID:    ev.TGID,
				Comm:    ev.Comm,
				Dst:     report.Dst(ev.Domain, ev.DAddr),
				DPort:   ev.DPort,
			})
		}
	}()

	select {
	case <-sig:
		slog.Info("shutting down")
	case err := <-readErr:
		return fmt.Errorf("reader error: %w", err)
	}
	return nil
}

// dnsExemptFor builds the port-53 exemption predicate used for verdict
// reporting, mirroring the kernel enforcement: with no policy every DNS
// destination is exempt (nil predicate); with allow_all_dns everything is
// exempt; otherwise only loopback and the discovered system resolvers are.
// Non-exempt port-53 connections are evaluated against the allowlist, so a
// denied DNS connection is reported as DENY rather than hidden as SKIP(dns).
func dnsExemptFor(engine *policy.Engine, resolvers []net.IP) report.DNSExempt {
	if engine == nil {
		return nil // no policy: port 53 is unrestricted, mirror as exempt
	}
	if engine.AllowAllDNS() {
		return func(net.IP) bool { return true }
	}
	set := make(map[string]struct{}, len(resolvers))
	for _, ip := range resolvers {
		set[ip.String()] = struct{}{}
	}
	return func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if ip.IsLoopback() {
			return true
		}
		_, ok := set[ip.String()] // v4-mapped IPv6 canonicalizes to dotted quad
		return ok
	}
}

// seedAllowlist primes the enforcement maps with the policy's explicit IP and
// CIDR entries and the current IPv4/IPv6 addresses of each allowlisted domain.
// This lets
// connections to already-resolvable destinations succeed on the first attempt
// rather than relying solely on observed DNS responses. Resolution failures are
// logged and skipped; the domain can still be permitted later when its DNS
// response is observed.
func seedAllowlist(w *ebpf.Watcher, engine *policy.Engine) {
	// Reflect the DNS policy: by default port 53 is restricted to configured
	// resolvers and loopback; allow_all_dns opts back into permitting any
	// port-53 destination.
	if err := w.SetAllowAllDNS(engine.AllowAllDNS()); err != nil {
		slog.Warn("set allow_all_dns failed", "error", err)
	}
	for _, ip := range engine.IPs() {
		if err := w.AllowIP(ip); err != nil {
			slog.Warn("seed allowed IP failed", "ip", ip.String(), "error", err)
		}
	}
	for _, cidr := range engine.CIDRs() {
		if err := w.AllowCIDR(cidr); err != nil {
			slog.Warn("seed allowed CIDR failed", "cidr", cidr.String(), "error", err)
		}
	}
	// Resolve the allowlisted domains concurrently: each lookup can take up to
	// seedLookupTimeout, so a serial loop delayed startup by domains×timeout in
	// the worst case. A bounded worker pool caps in-flight lookups so a large
	// allowlist cannot spawn an unbounded number of goroutines/sockets. Results
	// are collected per domain and the enforcement map is written afterwards
	// from this single goroutine, so no concurrent map access is involved.
	domains := engine.Domains()
	type seedResult struct {
		domain string
		ips    []net.IP
		err    error
	}
	results := make([]seedResult, len(domains))
	const maxConcurrentLookups = 8
	sem := make(chan struct{}, maxConcurrentLookups)
	var wg sync.WaitGroup
	var resolver net.Resolver
	for i, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			// "ip" resolves both A and AAAA records so IPv4 and IPv6
			// destinations are seeded. Each lookup is bounded by
			// seedLookupTimeout so a slow or unreachable resolver cannot block
			// startup indefinitely.
			ctx, cancel := context.WithTimeout(context.Background(), seedLookupTimeout)
			defer cancel()
			ips, err := resolver.LookupIP(ctx, "ip", domain)
			results[i] = seedResult{domain: domain, ips: ips, err: err}
		}(i, domain)
	}
	wg.Wait()

	for _, r := range results {
		if r.err != nil {
			slog.Warn("seed: resolve failed (will rely on observed DNS)", "domain", r.domain, "error", r.err)
			continue
		}
		for _, ip := range r.ips {
			if err := w.AllowIP(ip); err != nil {
				slog.Warn("seed allowed IP failed", "ip", ip.String(), "domain", r.domain, "error", err)
			}
		}
	}
}
