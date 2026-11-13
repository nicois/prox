# prox — Transparent Best-Effort MITM TLS Proxy (Design)

Date: 2026-11-02
Status: approved in chat; pending written-spec review

## 1. Purpose

A Linux gateway service (`prox`) that passively intercepts TLS (and plain
HTTP) traffic from machines routed through it. For each TLS connection it
makes a **best-effort MITM attempt**: it presents a short-lived leaf
certificate for the target host, signed with a compromised eMudhra
intermediate private key (Oct 2026 incident). Devices that do not properly
verify Certificate Transparency or revocation (a substantial fraction of
smart-home/IoT fleets) will accept the forged chain, and the proxy then
terminates TLS and logs the complete decrypted application stream.

The scope is **purely passive**: observe, log, forward. The proxy never
rewrites, blocks, or injects application data. Collected data is the
deliverable — it identifies the devices and gives other agents
comprehensive connection data to work with.

### Non-goals

- Active traffic manipulation (rewriting, filtering, injection).
- UDP/QUIC/HTTP3, IPv6, DNS resolution.
- Client-cert authority (we forward device client certs, never issue them).
- High-throughput ISP-scale operation (target: home/LAN gateway, hundreds of
  concurrent connections).

## 2. Background: the eMudhra incident (2026-10)

Facts used by the design:

- 2025-04-30: eight eMudhra "G3" intermediate TLS CAs (ECC, under the
  eMudhra ECC root) were created at a key ceremony whose key wrap/unwrap step
  produced weak key pairs; the weak keys are the ones published to browser
  root stores (one key had value `4`).
- 2026-10-17: disclosure that all eight intermediate keys are crackable.
- 2026-10-17 22:59 UTC: Mozilla OneCRL blocks all eight intermediates; all
  standard-config Firefox users patched without update/restart.
- 2026-10-18: all eight intermediates revoked; the browser root programs
  distrusted the parent ECC root as a precaution. NSS 3.131.1 (2026-10-20)
  removes the root from Mozilla's store; Apple/Google/Windows store updates
  roll out over subsequent weeks.
- The eight intermediates **never issued an end-entity certificate**, so no
  legitimate cert exists in the wild (or in CT logs) signed by them.

Consequences for this design:

- A forged leaf chains: trusted ECC root (still in unpatched stores) →
  compromised intermediate (structurally valid) → our leaf. It validates on
  any client that (a) has not yet removed/distrusted the root or blocked the
  intermediate, and (b) does not fail-closed on revocation. That population
  is exactly the target: smart devices that skip CT and revocation.
- Clients that have patched will reject with a TLS alert during/after the
  handshake. We use that failure signal: the (client, host) pair is recorded
  as patched and all subsequent connections are dropped (the rejection is
  logged); raw pass-through is available as an opt-in
  (`mitm.tunnel_fallback`).
- Modern browsers enforce CT. A leaf with validity ≤ 39.7 days requires SCTs
  from only one CT log (CA/B Forum short-lived rule), which we embed by
  submitting to a public log. Without an SCT, CT-checking browsers fail and
  flow to the patched path — acceptable for best-effort.

## 3. Architecture

```
                       +---------------- gateway (Linux) ----------------+
 devices  ──443/80──▶  │  iptables/nftables TPROXY                      │
   (LAN)               │      │                                         │
                       │      ▼                                         │
                       │  prox (Go, single binary)                      │
                       │   per-conn ladder:                             │
                       │    1. orig dst + sniff first bytes             │
                       │    2. plain HTTP  → parse+log, pipe upstream   │
                       │    3. TLS: SNI+JA3                             │
                       │         patched? → drop (tunnel: opt-in)       │
                       │         else   → MITM attempt                  │
                       │            ok  → TLS legs + tee to data sink   │
                       │            fail→ mark patched, client retries  │
                       │      │                        │                │
                       └──────┼────────────────────────┼────────────────┘
                              ▼                        ▼
                        WAN (real dst)        data sink (JSONL + SQLite)
```

Components (single Go binary, Go 1.27, stdlib + `modernc.org/sqlite`):

- **capture**: installs/maintains TPROXY rules; transparent listener.
- **ladder**: per-connection dispatch (section 4).
- **mitm**: forged-leaf minting, SCT submission, handshake management,
  patched-pair store.
- **sink**: per-connection data files + SQLite index + retention.

## 4. Traffic capture

- Mechanism: `iptables` TPROXY, IPv4 only (v1).
  - `iptables -t mangle -N DIVERT`
  - `iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT`
  - `iptables -t mangle -A DIVERT -j MARK --set-mark 1`
  - `iptables -t mangle -A DIVERT -j ACCEPT`
  - `ip rule add fwmark 1 lookup 100`
  - `ip route add local 0.0.0.0/0 dev lo table 100`
  - `iptables -t mangle -A PREROUTING -p tcp --dport <port> -j TPROXY --tproxy-mark 0x1/0x1 --on-port <proxyport>`
    (one rule per captured port; default ports: 80, 443)
- TPROXY (vs REDIRECT) is required because it preserves the **original
  destination** (IP-literal targets are common on IoT) and the client IP.
  Upstream replies to our own dial are delivered via the `-m socket` DIVERT
  path, so no self-interception loop.
- Listener binds `IP_TRANSPARENT` (via `syscall.SetsockoptInt`) and accepts.
  The original destination is the accepted socket's `LocalAddr`
  (getsockname): TPROXY preserves the original tuple on the socket, and the
  accepted child inherits `IP_TRANSPARENT`, which distinguishes TPROXY
  connections from ordinary ones (fallback: `RemoteAddr`).
- Rules are installed idempotently at service start (systemd `ExecStart`
  wrapper or in-process before listen), removed best-effort at stop.
- Captured ports are configurable; the ladder treats any port as TLS or
  plain TCP by content, not by port.

## 5. Connection ladder

For each accepted connection:

1. **Identify**: read original dst `(ip, port)`; capture client IP.
2. **Peek** first bytes (bounded read, ≤64 KiB):
   - Bytes parse as an HTTP request (request-line + headers) → **plain
     HTTP mode** (section 5.1).
   - Bytes are a TLS ClientHello → parse SNI, compute JA3, note offered
     ALPN/client-cert → **TLS mode** (section 5.2).
   - Neither → **raw TCP mode**: byte-faithful tunnel to original dst; log
     both raw streams.
3. SNI peek is done without completing a handshake, via
   `tls.Config.GetConfigForClient` over a read-only conn wrapper (or
   equivalent manual ClientHello parse). Peeked bytes are always
   re-injected verbatim downstream — they are restored, not rewritten.

### 5.1 Plain HTTP mode

- Parse the first request (method, host, path, version, headers, body framing via
  Content-Length or chunked encoding).
- Dial original dst; write the peeked bytes verbatim, then bidirectional
  `io.Copy` with `CloseWrite` on half-close.
- Log request/response pairs as structured events (headers parsed, body
  extracted to `body-*.bin`), plus the raw streams.
- If the first request is followed by keep-alive requests, continue parsing
  the c2s stream and emitting request/response events for the lifetime of
  the connection (bounded by the log cap).

### 5.2 TLS mode

- If `(client_ip, host)` is in the **patched store** (and within recheck
  interval) → the fallback is decided by `mitm.tunnel_fallback`:
  - **false (default): drop** — close the connection and log the stored
    rejection reason (`mitm result=patched_drop reason=<stored reason>`);
    the `mitm_attempt` meta event carries the same. No upstream dial, no
    hook gate, no bytes propagated: the client's ClientHello and the
    server's flight must not cross the proxy verbatim.
  - **true (opt-in): pass-through mode** — raw tunnel to original dst;
    log ClientHello fingerprint (SNI, JA3, ciphers, client cert if
    offered) and both raw TLS record streams. The tunnel propagates both
    TLS negotiations between the legs, so it is a recovery mechanism for
    a pinned device, not a capture.
- Otherwise → **MITM attempt**:
  1. Obtain/forge a leaf cert for the host (section 6).
  2. Run `tls.Server` on the client leg with that leaf
     (`GetCertificate` per SNI), **requesting a client certificate with an
     empty acceptable-CA list** (so mTLS-capable devices present theirs;
     recorded as a strong device identifier).
  3. Only *after* the client leg's handshake completes (so it is known
     whether the device presented a client cert) dial the original dst and
     complete a standard TLS client handshake with normal system-root
     verification (verification outcome is logged; a failed verification
     does not abort — best effort). Sequential rather than parallel: the
     upstream Certificate flight must not go out before the device cert is
     known; the cost is one LAN RTT of connection-setup latency, and a
     rejecting/patched device never triggers an upstream dial. If the
     upstream server requests a client cert and the device presented one,
     present the device's chain. Known limitation: the proxy does not hold
     the device's private key, so a strict-mTLS server (key-possession
     check via `CertificateVerify` / signed key exchange) will reject the
     handshake; this is logged as `upstream_mtls`, recorded in the patched
     store with that reason (the pair is un-MITMable without the device
     key), and subsequent attempts are dropped by default (tunneling —
     which restores the device's normal connectivity — requires
     `mitm.tunnel_fallback: true`).
  4. **Success** (client handshake completes): bidirectional `io.Copy` of
     decrypted application data, teed to the data sink (section 7). This
     covers h2 (via ALPN `h2`), `http/1.1`, and non-HTTP ALPNs (raw app
     data logged either way).
  5. **Failure** (client TLS alert or EOF before `Finished`):
     - Certificate-related alert (`certificate_unknown`, `unknown_ca`,
       `bad_certificate`, `decrypt_error`) → record `(client_ip, host)` in
       the patched store immediately.
     - Other failures (`user_canceled`, reset, timeout) → record after 2
       failed attempts against the same pair (guards against transient
       device restarts).
     - The connection is dead at that point; the device's next attempt
       is dropped (or tunnels, if `mitm.tunnel_fallback` is enabled).
       Log the attempt with the alert type.
- Upstream-side failures (dial/verify error on the leg to the real
  server) are **not** patched signals: log `upstream_error`, close, let
  the client retry. Exception: an upstream **mTLS requirement** the
  keyless proxy cannot satisfy (step 3 above) is recorded in the patched
  store with reason `mtls` — the pair can never be MITM'd without the
  device key, so its connections are dropped thereafter unless
  `mitm.tunnel_fallback` is enabled.

### Passivity invariants

- No byte of application data is altered; the only bytes the proxy writes
  are (a) peeked bytes restored verbatim, (b) the TLS handshake it is
  required to perform, (c) TLS records framing the teed app data.
- No idle/total deadlines shorter than typical IoT keepalive intervals
  (default: none on established tunnels; 60 s on handshake-phase reads).
- `CloseWrite` half-close semantics forwarded in both directions.
- Per-connection log size cap (default 256 MiB total across all files): on
  cap, logging stops but the connection continues; `conn_close` records
  `log_cap`.
- Disk guard: if free space < max(1 GiB, 10% of dataroot fs), new MITM
  attempts are skipped (pass-through instead) until space recovers.

## 6. Forged-leaf minting

Configuration supplies one or more compromised intermediate CA pairs
(cert PEM + private key PEM), used round-robin:

- Leaf key: ECDSA P-256.
- Subject: `CN = <SNI>`.
- SAN: `dNSName = <SNI>` when a hostname; if the original dst is an IP
  literal, include it as `iPAddress` (and keep SNI SAN if both present). If no SNI is present at all, SAN = {`iPAddress: <dst>`} and `CN = <dst>`.
- Validity: `NotBefore = now − 7d`, `NotAfter = now + 7d` (14 days total,
  ≤ 39.7d ⇒ single CT-log SCT required).
- Extensions: `keyUsage` digitalSignature; `extendedKeyUsage`
  serverAuth; `basicConstraints` CA:false; AKI from intermediate; SKI;
  serial: 16-byte random positive; `ct_precert_scts` absent,
  `signedCertificateTimestampList` (1.3.6.1.4.1.11129.2.4.2) present when
  an SCT is obtained.
- AIA/OCSP: inherited from the real intermediate (our serial is unknown to
  the real responder → fail-open clients continue; fail-closed clients
  patch us out, which is the intended signal).
- **SCT**: submit the leaf (chain: leaf + intermediate) to a configured
  public CT log `addchain` endpoint; embed the returned SCT. One retry on
  failure; if still failing, present the leaf without an SCT (log
  `sct_embedded: false`) — non-CT-checking clients still succeed.
- **Cache**: per host (SNI or IP), reuse the leaf while
  `now < NotAfter − 1d`; otherwise re-mint.
- Leaf generation cost is one ECDSA op per host per ~6 days — negligible.

## 7. Data sink

### Layout

```
<dataroot>/
  index.db                        # SQLite index (modernc.org/sqlite)
  conns/<YYYYMMDD>/<connid>/            # connid = <unix-ms>-<4 hex chars>
    meta.jsonl                    # structured events, one per line
    c2s.bin                       # client→server stream
    s2c.bin                       # server→client stream
    body-<n>.bin                  # extracted HTTP bodies (referenced by meta)
```

- `c2s.bin` / `s2c.bin` semantics per mode:
  - MITM success: decrypted application bytes, both directions, in arrival
    order (byte-faithful).
  - Pass-through / raw TCP: the raw on-wire bytes (TLS record stream or
    plain bytes), both directions.
- `meta.jsonl`: JSON Lines, UTF-8, one event per line. Agents read structure
  from JSON and payload from the `.bin` files via byte ranges — no base64,
  no custom binary framing. The first line is a `meta` event recording the
  prox build (git commit, link-time stamped) that wrote the stream.

### meta.jsonl event schema

| type | fields |
|---|---|
| `conn_open` | `ts` (unix ms), `conn_id`, `mode` (`mitm`\|`passthrough`\|`plain`\|`tcp`), `client_ip`, `client_port`, `dst_ip`, `dst_port`, `sni?`, `ja3?`, `alpn_offer?`, `client_cert_sha256?` |
| `leaf_presented` | `ts`, `cn`, `valid_until`, `chain` (subject CNs, leaf first), `sct` (bool), `sig` — emitted when a leaf was minted, before the client handshake: what the client leg was presented, so a rejection is analyzable from the log alone |
| `mitm_attempt` | `ts`, `result` (`success`\|`alert:<tls-alert>`\|`eof`\|`upstream_mtls`), `attempts` (for this pair), `leaf_sha256`, `sct_embedded` (bool) |
| `tls_client_leg` | `ts`, `version`, `cipher_suite`, `alpn`, `client_cert: {subject, sha256} \| null` |
| `tls_upstream_leg` | `ts`, `version`, `cipher_suite`, `alpn`, `server_cert_sha256`, `server_chain_sha256[]`, `verified` (bool), `verify_error?` |
| `http_request` | `ts`, `seq`, `c2s_bytes` [start,end) covering the full raw request, `method`, `host`, `path`, `http_version`, `headers`, `body_bytes` [start,end) \| null, `body_file?` |
| `http_response` | `ts`, `seq`, `s2c_bytes` [start,end), `status`, `http_version`, `headers`, `body_bytes` \| null, `body_file?` |
| `h2_frame` (MITM, ALPN `h2`) | `ts`, `dir` (`c2s`\|`s2c`), `stream_id`, `frame_type`, `flags`, `length`, `bytes` [start,end) within the corresponding `.bin` |
| `record_summary` (pass-through/tcp) | `ts`, `c2s_records?`, `s2c_records?`, `first_record_types?` |
| `conn_close` | `ts`, `duration_ms`, `c2s_bytes`, `s2c_bytes`, `reason` (`eof_client`\|`eof_server`\|`rst`\|`log_cap`\|`upstream_error`\|`mitm_failed`\|`cap_disk`) |

Byte ranges in `http_request`/`http_response` refer to offsets within the
corresponding `.bin` file and exactly tile the request/response regions.
`body_bytes` spans the body's **raw wire bytes** (including chunk framing
when `Transfer-Encoding: chunked` is used); `body-*.bin` holds the
transfer-decoded body. Testable invariant: concatenated request/response
ranges tile the file, and `sha256(body file) == sha256(decode(raw body
range))` — a plain byte equality when no transfer coding is present.
`Content-Encoding` is recorded in the event but not decoded in v1 (the
consumer decodes).

Structural parsing in v1: `http_request`/`http_response` events are emitted
for cleartext and `http/1.1` connections. For ALPN `h2`, `h2_frame` events
(9-byte frame header parse; HPACK header-block decoding is a follow-up) are
emitted alongside the raw byte stream, which remains the source of truth for
analysis.

### index.db schema

```sql
CREATE TABLE devices (
  ip           TEXT PRIMARY KEY,
  ja3          TEXT,            -- most frequent
  first_seen   INTEGER,         -- unix ms
  last_seen    INTEGER,
  conn_count   INTEGER,
  mitm_ok      INTEGER,
  mitm_fail    INTEGER
);
CREATE TABLE conns (
  id          TEXT PRIMARY KEY,
  ts          INTEGER,
  device_ip   TEXT,
  host        TEXT,             -- SNI or dst IP
  port        INTEGER,
  mode        TEXT,             -- 'mitm'|'passthrough'|'plain'|'tcp'
  result      TEXT,             -- conn_close reason
  dir         TEXT,
  c2s_bytes   INTEGER,
  s2c_bytes   INTEGER,
  duration_ms INTEGER
);
CREATE TABLE patched (
  ip           TEXT,
  host         TEXT,
  reason       TEXT,             -- 'cert_rejected'|'other'|'mtls'
  first        INTEGER,
  last_recheck INTEGER,
  attempts     INTEGER,
  PRIMARY KEY (ip, host)
);
CREATE INDEX idx_conns_ts ON conns(ts);
CREATE INDEX idx_conns_host ON conns(host);
```

### Retention

Configured `max_age` (default 90 d) and `max_size` (default 200 GiB); a
background cleaner deletes oldest `conns/<day>/` dirs and matching `conns`
rows. `devices` and `patched` survive cleanup.

## 8. Patched-pair store

- Backed by `index.db:patched` (persists across restarts); each row carries
  the reason (`cert_rejected`, `other`, `mtls`).
- `patched_recheck` (default 720 h): after this interval a pair is tried
  with a fresh MITM attempt once (catches re-imaged devices reusing a DHCP
  lease). Success removes the row; failure re-records it.
- Lookups are in-memory (LRU) over the SQLite table; table is small
  (pairs, not bytes).

## 9. Configuration

YAML file (path via flag) + command-line overrides:

```yaml
listen: "0.0.0.0:31280"        # TPROXY on-port
ports: [80, 443]               # captured dports
dataroot: "/var/lib/prox"
ca:                            # compromised intermediates, round-robin
  - cert_pem: /etc/prox/intermediate-1.crt
    key_pem:  /etc/prox/intermediate-1.key
mitm:
  validity_days: 7             # total window ±7d around now
  remint_before_expiry: 24h
  ct_log_url: "https://<log>/ct/v1/get-sth/addchain"
  patched_recheck: 720h
  tunnel_fallback: false       # patched-pair fallback: false = drop + log
                               # the stored rejection reason (default);
                               # true = raw tunnel (propagates both TLS
                               # negotiations)
log:
  per_conn_max_bytes: 268435456   # 256 MiB
  retention_max_age: 90d
  retention_max_size: 214748364800  # 200 GiB
  file_mode: 0600               # capture file perms at creation (octal;
                                # AGENTS.md stays 0644, not covered)
  dir_mode: 0700                # capture dir perms at creation (octal)
rules:
  mode: managed             # managed (default): prox installs the rules
                            # at startup and removes them at shutdown;
                            # consumer: operator/host owns the diversion,
                            # prox installs and removes nothing
  fwmark: 1
  routing_table: 100
  ifaces: ["eth0"]          # optional: capture only traffic arriving on
                               # these interfaces (container traffic arrives
                               # on the bridge's veth ports, so it is
                               # excluded)
```

## 10. Operational notes

- Single static binary; systemd unit running as a dedicated user;
  `CAP_NET_ADMIN` (or root) for rule management.
- Structured JSON logs to stderr → journald; `-log-level` flag
  (`debug|info|warn|error`, default `info`).
- pprof endpoint on a localhost admin socket (optional flag).

## 11. Verification plan

Development is **test-first (TDD)** on the **Go 1.27** toolchain (`go 1.27`
in `go.mod`): each component's tests are written before its implementation,
and a component is considered done only when its tests pass.

Time-dependent behaviors (patched-pair recheck interval, leaf re-mint
threshold, retention window, deadline expiry) are unit-tested with
`testing/synctest` (standard library in Go 1.27): inside a `synctest.Test` bubble the `time` package runs on a fake
clock, so multi-day intervals are advanced virtually via `synctest.Wait`
and `time.Sleep` instead of real waiting, and `synctest.Sleep` (new in
1.27) is used where a goroutine sleeps. Documented caveats are respected:
network I/O is not durably blocked inside a bubble, so I/O-bound tests use
in-process pipes (`net.Pipe`) or stay in the client-side smoke run; and
bubbles are flat — no `t.Run` subtests, `t.Parallel`, or `t.Deadline`
inside one, so each time-based test is a single top-level test function.

The original netns rig (two netns joined by veth, TPROXY in the gateway
netns) was rescoped during implementation — it needs `CAP_NET_ADMIN` and
could not run in the development environment. It is replaced by in-process
tests that pin the ladder's per-connection decisions and the CT fallback,
plus a client-side smoke script (`deploy/smoke.sh`, curl + openssl only)
run against a deployed proxy on a transparently intercepted network:

1. **MITM success**: Go test client whose `Roots` pool contains the
   eMudhra ECC root and the compromised intermediate (Go's TLS performs no
   CT check by default and no CRL/OCSP unless configured — the
   unpatched-client model) connecting to a local
   upstream TLS server → assert: forged leaf accepted, `meta.jsonl`
   contains `mitm_attempt result=success`, `http_request`/`http_response`
   events, `.bin` payload matches the exact bytes the client sent.
2. **Patch detection**: client pinned to a different CA (rejects forged
   chain with `unknown_ca`) → assert: cert alert captured with the
   handshake error in the log and the `mitm_attempt` meta event, `patched`
   row written, second connection to the same pair is dropped with
   `result=patched_drop` and the stored rejection reason (no upstream
   dial) — the default; with `mitm.tunnel_fallback: true` it instead
   tunnels (client sees the real upstream cert, bytes intact).
3. **Plain HTTP**: client on port 80 → assert request/response logged and
   forwarded byte-identical.
4. **Keep-alive + close**: multiple requests on one connection, then
   client close → `conn_close reason=eof_client`, byte ranges tile the
   stream, body files hash-match the transfer-decoded body ranges
   (byte-equal when unchunked).
5. **Unit**: SNI peek, JA3 vector tests, forged-leaf fields (SAN, validity,
   SCT embedding, extensions), patched-store state machine (alert-class →
   immediate; other → after 2), byte-range invariant checker.

End-to-end check on the real fleet is out of scope for the implementation
phase (the service is passive; a dry-run mode logging without MITM may be
added if requested).

## 12. Tech stack

- Go 1.27, stdlib: `net`, `syscall` (`IP_TRANSPARENT`, `getsockopt`,
  `getsockname`), `crypto/tls` (handshakes, `GetCertificate`),
  `crypto/x509` (`CreateCertificate`), `net/http`, `io` tees.
- `modernc.org/sqlite` (pure-Go SQLite) for `index.db`.
- CT log submission via plain HTTPS POST to the configured log endpoint.
- No other dependencies.

## 13. Extensibility: connection hooks (2026-11-05 addendum)

The relay is extensible through `pkg/hooks`, a small observer/interceptor
API registered by the consumer (not configured in YAML). The stock binary
ships with zero hooks: every relay path is a plain `io.Copy` with zero
overhead, and registering hooks adds per-connection cost only for
connections whose `Match` filter matches.

- `Hook` interface: `Filter() Match` (src/dst, dest port — empty fields
  are wildcards),
  `OnOpen(*Conn, *HookConn) Result` (may veto the connection before the
  upstream dial),
  `OnData(*Conn, Dir, []byte) Result` (observe; may replace the chunk
  (`Data`) or close the connection (`Close` + `Reason`)),
  `OnClose(*Conn, reason)` (notified exactly once).
- The hook chain runs per direction, in registration order. `Result` is
  cumulative across hooks (one hook may drop a chunk, a later one still
  sees it) and short-circuits on the first close.
- The bytes that actually reach the wire are what the sink captures
  (`c2s.bin`/`s2c.bin` append what was forwarded; a dropped chunk is a
  hole in the contiguous capture, reflected by a gap in the
  `bytes_c2s`/`bytes_s2c` ranges). Hook closes are recorded as
  `record_summary reason=hook` + `conn_close err="prox: hook close: <reason>"`.
- Push path: `OnOpen` also hands the hook a per-connection `*HookConn`:
  `WriteC2S`/`WriteS2C` inject hook-manufactured bytes, `Ready()` closes
  when the relay's legs are established (writes before that fail with
  `ErrNotReady`), `Done()` closes when the connection ends. Hook writes
  share the relay's per-direction writer — captured in the sink like
  relayed bytes, serialized with the relay's own writes to the same
  direction, never reprocessed through the hook chain. The pattern this
  enables: block the real server's messages in `OnData` and manufacture
  replacements from a goroutine started in `OnOpen` (see
  `TestLadderHookManufacturesServerMessages`).
- Wiring: `prox.New(cfg)` returns the facade; `Register(hook)` adds hooks;
  `Run`/`Shutdown` are unchanged. See `example/hooks/` (separate module,
  `replace prox => ../..`) for a working consumer: a passive SNI logger and
  a token redactor.
