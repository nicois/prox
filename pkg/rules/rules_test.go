package rules

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestBuildRules(t *testing.T) {
	cmds := BuildRules(Params{
		OnPort:       31280,
		Ports:        []int{80, 443},
		FWMark:       1,
		RoutingTable: 100,
	})
	want := []Cmd{
		{Bin: "iptables", Args: []string{"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "MARK", "--set-xmark", "0x1/0xffffffff"}},
		{Bin: "iptables", Args: []string{"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-m", "mark", "--mark", "0x1", "-j", "ACCEPT"}},
		{Bin: "ip", Args: []string{"rule", "add", "fwmark", "1", "lookup", "100"}},
		{Bin: "ip", Args: []string{"route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"}},
		{Bin: "iptables", Args: []string{"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "TPROXY", "--tproxy-mark", "0x1/0xffffffff", "--on-port", "31280"}},
		{Bin: "iptables", Args: []string{"-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "TPROXY", "--tproxy-mark", "0x1/0xffffffff", "--on-port", "31280"}},
	}
	if len(cmds) != len(want) {
		t.Fatalf("BuildRules len = %d, want %d\n%v", len(cmds), len(want), cmds)
	}
	for i, c := range cmds {
		if c.Bin != want[i].Bin || strings.Join(c.Args, " ") != strings.Join(want[i].Args, " ") {
			t.Fatalf("cmd[%d] = %s %v, want %s %v", i, c.Bin, c.Args, want[i].Bin, want[i].Args)
		}
	}
}

// TestBuildRulesIfaceScoping: with Ifaces set, exactly one TPROXY rule is
// installed per (port, iface) pair (iptables -i is single-valued: a second
// -i on the same rule overwrites the first), and the -D mirrors match;
// empty Ifaces keeps one unscoped rule per port.
func TestBuildRulesIfaceScoping(t *testing.T) {
	p := Params{OnPort: 31280, Ports: []int{80, 443}, FWMark: 1, RoutingTable: 100, Ifaces: []string{"eth0", "eth1"}}

	pairs := func(cmds []Cmd) map[string]bool {
		m := map[string]bool{}
		for _, c := range cmds {
			if !slices.Contains(c.Args, "TPROXY") {
				continue
			}
			n := 0
			for _, a := range c.Args {
				if a == "-i" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("TPROXY rule has %d -i flags, want exactly 1: %v", n, c.Args)
			}
			var port, iface string
			args := c.Args
			for i := 0; i+1 < len(args); i++ {
				if args[i] == "--dport" {
					port = args[i+1]
				}
				if args[i] == "-i" {
					iface = args[i+1]
				}
			}
			if !m[port+":"+iface] {
				m[port+":"+iface] = true
			} else {
				t.Fatalf("duplicate (port, iface) TPROXY rule: %v", c.Args)
			}
		}
		return m
	}
	want := map[string]bool{"80:eth0": true, "443:eth0": true, "80:eth1": true, "443:eth1": true}
	for name, cmds := range map[string][]Cmd{"build": BuildRules(p), "remove": BuildRemove(p)} {
		if got := pairs(cmds); len(got) != len(want) {
			t.Fatalf("%s: %d (port, iface) TPROXY rules, want %d: %v", name, len(got), len(want), got)
		} else {
			for k := range want {
				if !got[k] {
					t.Fatalf("%s: missing TPROXY rule for %s: %v", name, k, got)
				}
			}
		}
	}

	p.Ifaces = nil
	for _, c := range BuildRules(p) {
		if slices.Contains(c.Args, "-i") {
			t.Fatalf("unexpected -i without ifaces: %v", c.Args)
		}
	}
}

type fakeRunner struct {
	calls [][]string
	fail  func(args ...string) bool
}

func (f *fakeRunner) Run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail != nil && f.fail(args...) {
		return fmt.Errorf("fake failure: %v", args)
	}
	return nil
}

// TestRemoveIsSymmetric: every rule BuildRules installs must be removed by
// BuildRemove, otherwise the proxy cannot restart after a clean shutdown
// (leftover PREROUTING rules keep diverting traffic to a dead chain).
func TestRemoveIsSymmetric(t *testing.T) {
	p := Params{OnPort: 31280, Ports: []int{80, 443}, FWMark: 1, RoutingTable: 100}
	build := BuildRules(p)
	remove := BuildRemove(p)

	count := func(cmds []Cmd, bin string, sub ...string) int {
		n := 0
		for _, c := range cmds {
			if c.Bin == bin && containsAll(c.Args, sub...) {
				n++
			}
		}
		return n
	}
	if got, want := count(remove, "iptables", "-D", "PREROUTING"), count(build, "iptables", "-A", "PREROUTING"); got != want {
		t.Fatalf("PREROUTING deletes = %d, want %d (one per add)", got, want)
	}
	if !hasCmd(remove, "ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100") {
		t.Fatal("BuildRemove does not delete the local 0.0.0.0/0 route")
	}
	if !hasCmd(remove, "iptables", "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "MARK", "--set-xmark", "0x1/0xffffffff") {
		t.Fatal("BuildRemove does not delete the socket-mark rule")
	}
}

func hasCmd(cmds []Cmd, bin string, args ...string) bool {
	for _, c := range cmds {
		if c.Bin != bin || len(c.Args) != len(args) {
			continue
		}
		eq := true
		for i := range args {
			if c.Args[i] != args[i] {
				eq = false
				break
			}
		}
		if eq {
			return true
		}
	}
	return false
}

func containsAll(haystack []string, sub ...string) bool {
	for _, s := range sub {
		found := slices.Contains(haystack, s)
		if !found {
			return false
		}
	}
	return true
}

// TestRemoveContinuesAfterFailure: Remove must attempt every command even
// when an earlier one fails — bailing on the first error strands the
// remaining rules (leftover TPROXY rules keep diverting to a dead port).
func TestRemoveContinuesAfterFailure(t *testing.T) {
	r := &fakeRunner{fail: func(args ...string) bool { return slices.Contains(args, "-D") && slices.Contains(args, "80") }}
	p := Params{OnPort: 31280, Ports: []int{80, 443}, FWMark: 1, RoutingTable: 100}
	r.calls = nil
	err := Remove(r, p)
	if err == nil {
		t.Fatal("Remove returned nil despite a failing command")
	}
	if got, want := len(r.calls), len(BuildRemove(p)); got != want {
		t.Fatalf("Remove issued %d commands, want %d (all of them)", got, want)
	}
}

func TestApplyRemovesSymmetric(t *testing.T) {
	r := &fakeRunner{}
	p := Params{OnPort: 31280, Ports: []int{80, 443}, FWMark: 1, RoutingTable: 100}
	if err := Apply(r, p); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) == 0 {
		t.Fatal("Apply issued no commands")
	}
	if err := Remove(r, p); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != len(BuildRules(p))+len(BuildRemove(p)) {
		t.Fatalf("Apply+Remove issued %d calls, want %d", len(r.calls), len(BuildRules(p))+len(BuildRemove(p)))
	}
}
