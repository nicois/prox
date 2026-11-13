// Package config holds the proxy's runtime settings: a YAML file layered
// over the built-in production defaults (Default), command-line overrides,
// and validation. CA entries hold file paths, not PEM contents — the files
// are read lazily by the TLS machinery.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all runtime settings for the proxy.
type Config struct {
	Listen   string   `yaml:"listen"`
	Ports    []int    `yaml:"ports"`
	DataRoot string   `yaml:"dataroot"`
	CAPaths  []CAPath `yaml:"ca"`
	MITM     MITM     `yaml:"mitm"`
	Log      Log      `yaml:"log"`
	Rules    Rules    `yaml:"rules"`
	// Isolation is the client–upstream isolation mode:
	// "" or "off" is the normal relay; "full" accepts and captures c2s
	// (client-leg MITM included) with no upstream connection and nothing
	// sent to the client; "readonly" mirrors c2s to the real upstream but
	// captures s2c without delivering it to the client.
	Isolation string `yaml:"isolation"`
	// S2cMaxPacket, when > 0, caps the size of s2c chunks forwarded to the
	// client. The unit is a chunk: one upstream read delivery — one TLS
	// record on a MITM leg, one kernel delivery on a plain/raw leg. The
	// cap is all-or-nothing: a chunk larger than the cap is dropped whole,
	// a chunk within it is forwarded byte-exact; never partial. Dropped
	// chunks are still captured (the capture is the complete wire) and each
	// drop is logged as s2c_drop (journal info line + meta.jsonl event);
	// the record carries start/end offsets into s2c.bin — a discarded
	// chunk is extractable by offset.
	// Zero (the default) disables the cap. It has no effect under "full"
	// or "readonly" isolation (nothing, or no s2c, is delivered to the
	// client there). Consequence of dropping: a missing middle record
	// corrupts the client's application stream; the client typically
	// resets at the next record.
	S2cMaxPacket int `yaml:"s2c_max_packet"`
}

// CAPath is a compromised intermediate CA: a cert PEM file, its key PEM
// file, and an optional extra-chain PEM file (one or more CERTIFICATE
// blocks) appended after the intermediate when serving leaves — for clients
// whose trust store lacks the intermediate's issuer.
type CAPath struct {
	CertPEM  string `yaml:"cert_pem"`
	KeyPEM   string `yaml:"key_pem"`
	ChainPEM string `yaml:"chain_pem"`
}

// MITM holds forged-leaf minting parameters.
type MITM struct {
	ValidityDays      int           `yaml:"validity_days"`
	ReintBeforeExpiry time.Duration `yaml:"-"`
	CTLogURL          string        `yaml:"ct_log_url"`
	PatchedRecheck    time.Duration `yaml:"patched_recheck"`
	// UpstreamCAs are extra PEM files trusted when verifying the upstream
	// (real server) leg of a MITM, on top of the system roots — for
	// upstreams that present certs no system store trusts (vendor
	// self-signed). Empty = system roots only.
	UpstreamCAs []string `yaml:"upstream_cas"`
	// TunnelFallback controls the patched-pair fallback (design §5.2):
	// false (default, zero value) = a connection from a patched (ip,
	// host) pair is dropped and the stored rejection reason is logged
	// (result=patched_drop); true = the legacy pass-through tunnel
	// serves the pair verbatim, propagating both TLS negotiations
	// between the legs.
	TunnelFallback bool `yaml:"tunnel_fallback"`
}

// Log holds per-connection logging and retention parameters.
type Log struct {
	PerConnMaxBytes  int64         `yaml:"per_conn_max_bytes"`
	RetentionMaxAge  time.Duration `yaml:"retention_max_age"`
	RetentionMaxSize int64         `yaml:"retention_max_size"`
	// FileMode is the permission of capture files (c2s.bin, s2c.bin,
	// meta.jsonl) at creation time; existing files are not re-chmodded.
	// Write it unquoted octal in YAML (file_mode: 0600). The dataroot
	// data-doc AGENTS.md intentionally stays 0644 and is not covered.
	FileMode int `yaml:"file_mode"`
	// DirMode is the permission of capture directories (the dataroot and
	// each per-connection directory) at creation time; existing
	// directories are not re-chmodded. Write it unquoted octal in YAML
	// (dir_mode: 0700).
	DirMode int `yaml:"dir_mode"`
}

// Rules holds TPROXY rule parameters.
type Rules struct {
	// Mode selects who owns the TPROXY capture rules: "managed" (the
	// default) — prox installs the rules at startup (clearing stale
	// state first) and removes them at shutdown; "consumer" — prox
	// assumes the operator or embedding host has already diverted the
	// traffic (TPROXY to the listen address with the configured
	// fwmark/routing) and installs and removes nothing, including on
	// exit. Empty (a directly constructed Config) is treated as managed.
	Mode         string `yaml:"mode"`
	FWMark       uint32 `yaml:"fwmark"`
	RoutingTable uint32 `yaml:"routing_table"`
	// Ifaces restricts capture to traffic arriving on these interfaces
	// (e.g. the LAN port). Traffic from this host's own network namespaces
	// (containers) also transits PREROUTING but arrives on the bridge's
	// veth ports, so it is excluded; empty = all interfaces.
	Ifaces []string `yaml:"ifaces"`
}

// Default returns a Config populated with sensible production defaults.
func Default() *Config {
	return &Config{
		Listen:   "0.0.0.0:31280",
		Ports:    []int{80, 443},
		DataRoot: "/var/lib/prox",
		MITM: MITM{
			ValidityDays:      7,
			ReintBeforeExpiry: 24 * time.Hour,
			PatchedRecheck:    720 * time.Hour,
		},
		Log: Log{
			PerConnMaxBytes:  256 << 20,
			RetentionMaxAge:  90 * 24 * time.Hour,
			RetentionMaxSize: 200 << 30,
			FileMode:         0o600,
			DirMode:          0o700,
		},
		Rules:     Rules{Mode: "managed", FWMark: 1, RoutingTable: 100},
		Isolation: "off",
	}
}

// Load reads YAML at path, layers flag overrides on top, and validates. A path
// of "" or a missing file falls back to defaults. CAPaths hold file paths, not
// PEM contents (loaded lazily by tlsutil).
func Load(path string, overrides func(*Config)) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config: %w", err)
			}
		} else if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if overrides != nil {
		overrides(cfg)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	if len(c.Ports) == 0 {
		return fmt.Errorf("ports is required")
	}
	for _, name := range c.Rules.Ifaces {
		// 15 = IFNAMSIZ-1. iptables accepts a rule for a missing
		// interface, it just never matches; existence is checked at
		// startup.
		if name == "" || len(name) > 15 || strings.ContainsAny(name, " \t") {
			return fmt.Errorf("rules.ifaces: %q is not a valid interface name", name)
		}
	}
	switch c.Isolation {
	case "", "off", "full", "readonly":
	default:
		return fmt.Errorf("isolation: %q is not a valid mode (off, full, or readonly)", c.Isolation)
	}
	switch c.Rules.Mode {
	case "", "managed", "consumer":
	default:
		return fmt.Errorf("rules.mode: %q is not a valid mode (managed or consumer)", c.Rules.Mode)
	}
	if c.S2cMaxPacket < 0 {
		return fmt.Errorf("s2c_max_packet: %d is negative", c.S2cMaxPacket)
	}
	// A decimal value here almost always means the operator wrote the
	// mode unquoted-then-decoded wrong (600 instead of 0600): reject it
	// loudly instead of creating oddly-permissioned files.
	if c.Log.FileMode < 0 || c.Log.FileMode > 0o777 {
		return fmt.Errorf("log.file_mode: %d is not a valid mode (write it unquoted octal, e.g. file_mode: 0600)", c.Log.FileMode)
	}
	if c.Log.DirMode < 0 || c.Log.DirMode > 0o777 {
		return fmt.Errorf("log.dir_mode: %d is not a valid mode (write it unquoted octal, e.g. dir_mode: 0700)", c.Log.DirMode)
	}
	return nil
}
