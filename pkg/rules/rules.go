// Package rules builds the TPROXY capture ruleset as a list of argv
// commands (never a shell string) and applies or removes them.
package rules

import (
	"errors"
	"fmt"
)

// Params are the TPROXY rule parameters: the listener port the rules
// redirect to (OnPort), the captured destination ports, the socket mark and
// the local routing table for the return-path correction, and the optional
// interface restriction. They must match the proxy's config — the proxy
// re-applies the rules from these values at startup and removes them at
// shutdown.
type Params struct {
	OnPort       int
	Ports        []int
	FWMark       uint32
	RoutingTable uint32
	Ifaces       []string
}

// Cmd is one command to run: Bin plus Args, executed as a single argv
// (exec.Command, never a shell).
type Cmd struct {
	Bin  string
	Args []string
}

// Runner runs one command. prox uses a plain exec implementation; tests
// substitute a recorder.
type Runner interface {
	Run(name string, args ...string) error
}

// markSpec is the TPROXY mark with a full mask so the resulting skb mark
// equals FWMark exactly - the "ip rule fwmark N" then matches. A narrow
// mask (e.g. 0x1/0x1) would silently break for FWMark > 1.
func markSpec(p Params) string {
	return fmt.Sprintf("0x%x/0xffffffff", p.FWMark)
}

// BuildRules returns the commands that install the capture ruleset.
//
//   - `-m socket -j MARK --set-xmark`: established-phase fast path
//     (previously a DIVERT chain) - a packet whose tuple already has a
//     socket is marked so the "ip rule fwmark N lookup T" local route
//     delivers it to the transparent socket instead of forwarding it on.
//   - `ip rule fwmark N lookup T` + `ip route local 0.0.0.0/0 dev lo table
//     T`: the return-path correction above.
//   - `--dport P -j TPROXY --tproxy-mark ... --on-port ...`: captures new
//     connections to the real destination; the original destination is
//     preserved in the socket tuple, which the proxy reads via getsockname.
//
// When p.Ifaces is set, one TPROXY rule is installed per (port, iface)
// pair (-i takes a single interface, so one rule per pair): capture is
// restricted to traffic arriving on those interfaces. Traffic from this
// host's own network namespaces (e.g. podman containers) also transits
// PREROUTING but arrives on the bridge's veth ports, so it is not
// captured.
//
// --on-ip is intentionally omitted: the socket is bound to 0.0.0.0 and the
// original destination stays intact.
func BuildRules(p Params) []Cmd {
	cmds := []Cmd{
		{Bin: "iptables", Args: []string{"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "MARK", "--set-xmark", markSpec(p)}},
		{Bin: "iptables", Args: []string{"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-m", "mark", "--mark", fmt.Sprintf("0x%x", p.FWMark), "-j", "ACCEPT"}},
		{Bin: "ip", Args: []string{"rule", "add", "fwmark", fmt.Sprintf("%d", p.FWMark), "lookup", fmt.Sprintf("%d", p.RoutingTable)}},
		{Bin: "ip", Args: []string{"route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", fmt.Sprintf("%d", p.RoutingTable)}},
	}
	for _, c := range tproxyRules(p, "-A") {
		cmds = append(cmds, c)
	}
	return cmds
}

// tproxyRules builds the per-port TPROXY rules: one per (port, iface) pair,
// or one unscoped rule per port when Ifaces is empty. The add (-A) and
// delete (-D) forms must carry identical arguments or the removal no longer
// matches the installed rule.
func tproxyRules(p Params, addDel string) []Cmd {
	ifaces := p.Ifaces
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	var cmds []Cmd
	for _, port := range p.Ports {
		for _, name := range ifaces {
			args := []string{"-t", "mangle", addDel, "PREROUTING", "-p", "tcp"}
			if name != "" {
				args = append(args, "-i", name)
			}
			args = append(args, "--dport", fmt.Sprintf("%d", port), "-j", "TPROXY", "--tproxy-mark", markSpec(p), "--on-port", fmt.Sprintf("%d", p.OnPort))
			cmds = append(cmds, Cmd{Bin: "iptables", Args: args})
		}
	}
	return cmds
}

// BuildRemove returns the inverse commands of BuildRules, in reverse order
// (per-port TPROXY rules, then the socket-mark rules, then the ip route,
// then the ip rule).
func BuildRemove(p Params) []Cmd {
	cmds := []Cmd{}
	for _, c := range tproxyRules(p, "-D") {
		cmds = append(cmds, c)
	}
	cmds = append(cmds,
		Cmd{Bin: "iptables", Args: []string{"-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "mark", "--mark", fmt.Sprintf("0x%x", p.FWMark), "-j", "ACCEPT"}},
		Cmd{Bin: "iptables", Args: []string{"-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "MARK", "--set-xmark", markSpec(p)}},
		Cmd{Bin: "ip", Args: []string{"route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", fmt.Sprintf("%d", p.RoutingTable)}},
		Cmd{Bin: "ip", Args: []string{"rule", "del", "fwmark", fmt.Sprintf("%d", p.FWMark), "lookup", fmt.Sprintf("%d", p.RoutingTable)}},
	)
	return cmds
}

// Apply runs the BuildRules commands in order and stops at the first
// failure.
func Apply(r Runner, p Params) error {
	for _, c := range BuildRules(p) {
		if err := r.Run(c.Bin, c.Args...); err != nil {
			return fmt.Errorf("apply %s %v: %w", c.Bin, c.Args, err)
		}
	}
	return nil
}

// Remove runs the BuildRemove commands best-effort — every command is
// attempted and the failures joined — so one missing rule cannot strand the
// rest.
func Remove(r Runner, p Params) error {
	// Best-effort: attempt every command and join the failures. Bailing on
	// the first error would silently strand the remaining rules (e.g. a
	// missing port-80 rule leaving the port-443 rule live with no listener).
	var errs []error
	for _, c := range BuildRemove(p) {
		if err := r.Run(c.Bin, c.Args...); err != nil {
			errs = append(errs, fmt.Errorf("remove %s %v: %w", c.Bin, c.Args, err))
		}
	}
	return errors.Join(errs...)
}
