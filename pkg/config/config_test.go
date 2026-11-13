package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadRulesIfacesValidation: rules.ifaces entries must look like
// interface names; iptables accepts a rule for a missing interface but it
// never matches, so reject garbage at load (existence is checked at
// startup).
func TestLoadRulesIfacesValidation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := "listen: \"0.0.0.0:31280\"\nports: [443]\nrules:\n  ifaces:\n    - eth0\n    - eth1\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules.Ifaces) != 2 {
		t.Fatalf("ifaces = %v, want 2 entries", cfg.Rules.Ifaces)
	}
	for _, bad := range []string{"", "has space", strings.Repeat("a", 16)} {
		if _, err := Load(cfgPath, func(c *Config) { c.Rules.Ifaces = []string{bad} }); err == nil {
			t.Fatalf("Load accepted %q", bad)
		}
	}
}

// TestLoadDefaults verifies Default() populates the required fields.
func TestLoadDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Listen != "0.0.0.0:31280" {
		t.Fatalf("default listen = %q, want 0.0.0.0:31280", cfg.Listen)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != 80 || cfg.Ports[1] != 443 {
		t.Fatalf("default ports = %v, want [80 443]", cfg.Ports)
	}
	if cfg.MITM.PatchedRecheck == 0 || cfg.Log.PerConnMaxBytes == 0 {
		t.Fatal("default MITM/Log fields must be non-zero")
	}
}

// TestLoadYAMLAndOverrides verifies YAML fields parse and overrides win.
func TestLoadYAMLAndOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	wantListen := "127.0.0.1:9000"
	yaml := `
listen: "` + wantListen + `"
ports: [80, 443, 8883]
dataroot: "` + dir + `"
ca:
  - cert_pem: /etc/prox/intermediate-1.crt
    key_pem:  /etc/prox/intermediate-1.key
    chain_pem: /etc/prox/chain.crt
mitm:
  validity_days: 7
  patched_recheck: 720h
  upstream_cas: [/etc/prox/vendor-cert.pem]
log:
  per_conn_max_bytes: 268435456
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath, func(c *Config) {
		c.Listen = wantListen
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != wantListen {
		t.Fatalf("listen = %q, want %q", cfg.Listen, wantListen)
	}
	gotPort := false
	for _, p := range cfg.Ports {
		if p == 8883 {
			gotPort = true
		}
	}
	if !gotPort {
		t.Fatalf("ports missing 8883: %v", cfg.Ports)
	}
	if len(cfg.CAPaths) != 1 || cfg.CAPaths[0].CertPEM != "/etc/prox/intermediate-1.crt" || cfg.CAPaths[0].ChainPEM != "/etc/prox/chain.crt" {
		t.Fatalf("CA paths not parsed: %+v", cfg.CAPaths)
	}
	if len(cfg.MITM.UpstreamCAs) != 1 || cfg.MITM.UpstreamCAs[0] != "/etc/prox/vendor-cert.pem" {
		t.Fatalf("upstream_cas not parsed: %v", cfg.MITM.UpstreamCAs)
	}
}

// TestLoadMissingRequired verifies validate() rejects an empty listen.
func TestLoadMissingRequired(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(cfgPath, []byte("listen: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath, func(*Config) {}); err == nil {
		t.Fatal("expected error for empty listen")
	}
}

// TestLoadMissingFileDefaults verifies Load falls back to defaults when the
// config file does not exist.
func TestLoadMissingFileDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"), func(*Config) {})
	if err != nil {
		t.Fatalf("Load(missing): %v, want nil", err)
	}
	if cfg.Listen != Default().Listen || len(cfg.Ports) != 2 {
		t.Fatalf("missing file did not fall back to defaults: %+v", cfg)
	}
}

// TestLoadNilOverrides verifies Load tolerates a nil overrides callback.
func TestLoadNilOverrides(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), nil)
	if err != nil {
		t.Fatalf("Load(nil overrides): %v, want nil", err)
	}
	if cfg.Listen != Default().Listen {
		t.Fatalf("listen = %q, want default", cfg.Listen)
	}
}

// TestLoadIsolation verifies the isolation mode: the default is "off", each
// valid value parses from YAML, and a bad value is rejected naming it.
func TestLoadIsolation(t *testing.T) {
	if got := Default().Isolation; got != "off" {
		t.Fatalf("default isolation = %q, want off", got)
	}
	for _, want := range []string{"off", "full", "readonly"} {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("isolation: "+want+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(cfgPath, nil)
		if err != nil {
			t.Fatalf("Load(isolation=%q): %v", want, err)
		}
		if cfg.Isolation != want {
			t.Fatalf("isolation = %q, want %q", cfg.Isolation, want)
		}
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("isolation: tunnel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath, nil); err == nil {
		t.Fatal("expected error for isolation=tunnel")
	}
}

// TestLoadS2cMaxPacket verifies the s2c_max_packet cap: a positive value
// parses from YAML, a negative value is rejected naming the field, and an
// absent key leaves the default zero (disabled).
func TestLoadS2cMaxPacket(t *testing.T) {
	if got := Default().S2cMaxPacket; got != 0 {
		t.Fatalf("default S2cMaxPacket = %d, want 0 (disabled)", got)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("s2c_max_packet: 2048\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath, nil)
	if err != nil {
		t.Fatalf("Load(s2c_max_packet=2048): %v", err)
	}
	if cfg.S2cMaxPacket != 2048 {
		t.Fatalf("S2cMaxPacket = %d, want 2048", cfg.S2cMaxPacket)
	}
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("s2c_max_packet: -1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath, nil); err == nil || !strings.Contains(err.Error(), "s2c_max_packet") {
		t.Fatalf("Load(s2c_max_packet=-1) = %v, want error naming s2c_max_packet", err)
	}
	cfg, err = Load(filepath.Join(t.TempDir(), "missing.yaml"), nil)
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if cfg.S2cMaxPacket != 0 {
		t.Fatalf("S2cMaxPacket = %d, want 0 when absent", cfg.S2cMaxPacket)
	}
}

// TestLogCaptureModes verifies the log capture modes: the defaults are
// 0o600/0o700; unquoted YAML octal (file_mode: 0644) parses to that octal;
// a decimal value out of range (file_mode: 600 — an operator who meant
// 0600) is rejected with an error naming the field.
func TestLogCaptureModes(t *testing.T) {
	if got := Default().Log.FileMode; got != 0o600 {
		t.Errorf("default FileMode = %o, want 0600", got)
	}
	if got := Default().Log.DirMode; got != 0o700 {
		t.Errorf("default DirMode = %o, want 0700", got)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("log:\n  file_mode: 0644\n  dir_mode: 0755\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath, nil)
	if err != nil {
		t.Fatalf("Load(file_mode=0644): %v", err)
	}
	if cfg.Log.FileMode != 0o644 || cfg.Log.DirMode != 0o755 {
		t.Fatalf("capture modes = %o/%o, want 0644/0755 (unquoted YAML octal)", cfg.Log.FileMode, cfg.Log.DirMode)
	}
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("log:\n  file_mode: 600\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath, nil); err == nil || !strings.Contains(err.Error(), "file_mode") {
		t.Fatalf("Load(file_mode=600) = %v, want error naming file_mode", err)
	}
}

// TestLoadTunnelFallback verifies the mitm.tunnel_fallback knob: true
// parses from YAML, and an omitted key leaves the zero-value default
// (false — patched pairs are dropped and the rejection is logged, not
// tunneled).
func TestLoadTunnelFallback(t *testing.T) {
	if Default().MITM.TunnelFallback {
		t.Fatal("Default() must not enable tunnel_fallback (zero value false = drop)")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("listen: \"0.0.0.0:31280\"\nports: [443]\nmitm:\n  tunnel_fallback: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath, nil)
	if err != nil {
		t.Fatalf("Load(tunnel_fallback=true): %v", err)
	}
	if !cfg.MITM.TunnelFallback {
		t.Fatal("tunnel_fallback: true did not parse")
	}
	if err := os.WriteFile(cfgPath, []byte("listen: \"0.0.0.0:31280\"\nports: [443]\nmitm:\n  validity_days: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(cfgPath, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MITM.TunnelFallback {
		t.Fatal("omitted tunnel_fallback must default to false")
	}
}

// TestLoadRulesMode verifies rules.mode: the default is "managed" (prox
// owns the tproxy rules); "consumer" parses from YAML; any other value is
// rejected naming the field.
func TestRulesModeValidation(t *testing.T) {
	if got := Default().Rules.Mode; got != "managed" {
		t.Fatalf("default rules.mode = %q, want managed", got)
	}
	for _, want := range []string{"managed", "consumer"} {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("listen: \"0.0.0.0:31280\"\nports: [443]\nrules:\n  mode: "+want+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(cfgPath, nil)
		if err != nil {
			t.Fatalf("Load(mode=%s): %v", want, err)
		}
		if cfg.Rules.Mode != want {
			t.Fatalf("rules.mode = %q, want %q", cfg.Rules.Mode, want)
		}
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("listen: \"0.0.0.0:31280\"\nports: [443]\nrules:\n  mode: bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath, nil); err == nil || !strings.Contains(err.Error(), "rules.mode") {
		t.Fatalf("Load(mode=bogus) = %v, want error naming rules.mode", err)
	}
	// An omitted key leaves the default "managed" (a valid config
	// round-trips).
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), nil)
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if cfg.Rules.Mode != "managed" {
		t.Fatalf("rules.mode = %q when absent, want managed", cfg.Rules.Mode)
	}
}
