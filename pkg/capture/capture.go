// Package capture is the in-process, per-connection record of what prox's
// relay did with every byte chunk: forwarded (possibly transformed),
// dropped (with the hook's reason), held (with the holding hook's reason;
// resolved by a later Forwarded or Dropped record), or injected by a hook
// (with its origin). It is the readable counterpart of the file sink: the
// file capture under the dataroot stays one adapter of the same relay;
// this package is the API form, for hosts that embed prox and persist or
// audit the record themselves.
//
// The record is a pull API: a Stream is opened per connection, records
// append while the connection flows, and the host reads Chunks/Info any
// time — typically after Wait() closes. No per-connection goroutines.
//
// Embedded hosts (no dataroot) must call Registry.Evict themselves to bound
// the registry map, because the built-in eviction tick runs with the
// standalone retention loop.
package capture

import (
	"sync"
	"time"
)

// Dir is one direction of a proxied connection's byte stream.
type Dir int

const (
	// DirC2S is bytes flowing client -> upstream.
	DirC2S Dir = iota
	// DirS2C is bytes flowing upstream -> client.
	DirS2C
)

// String returns the direction's record name: "c2s" or "s2c".
func (d Dir) String() string {
	switch d {
	case DirC2S:
		return "c2s"
	case DirS2C:
		return "s2c"
	default:
		return "dir"
	}
}

// Decision is what happened to one chunk.
type Decision int

const (
	// Forwarded: the chunk (possibly transformed) went on the wire.
	Forwarded Decision = iota
	// Dropped: a hook removed the chunk; Reason carries the hook's reason.
	Dropped
	// Held: the chunk was buffered by a hook; Reason carries the
	// hook's reason. Released bytes are recorded Forwarded; bytes still
	// held at close are recorded Dropped with the close reason.
	Held
	// Injected: the chunk was manufactured by a hook; Origin names it.
	Injected
)

// String returns the decision's record name: "forwarded", "dropped",
// "held", or "injected".
func (d Decision) String() string {
	switch d {
	case Forwarded:
		return "forwarded"
	case Dropped:
		return "dropped"
	case Held:
		return "held"
	case Injected:
		return "injected"
	default:
		return "decision"
	}
}

// Chunk is one recorded chunk decision.
type Chunk struct {
	Dir      Dir
	TS       time.Time // receive time
	Len      int
	Decision Decision
	Reason   string // Dropped: the hook's reason
	Origin   string // Injected: the hook's name (Name() if it has one, else its type)
	// Payload is set only when the owning stream was opened with byte
	// capture enabled (Registry.EnableBytes); nil otherwise. It is a
	// copy of the chunk bytes at the record site — safe to retain.
	Payload []byte
}

// TLSInfo is the client-leg TLS outcome for a flow classified TLS.
type TLSInfo struct {
	Host    string // the client's SNI (may be an IP literal)
	Version uint16 // negotiated client-leg version; 0 when no handshake completed
	Result  string // "success" | "client_rejected" | "mint_failed"
}

// CloseInfo is the per-connection metadata that closes the record.
type CloseInfo struct {
	ID     string
	Kind   string // sniffed kind: "plain_http", "tls", "raw_tcp"
	SNI    string
	Client string // "host:port"
	Dst    string // "host:port"
	Opened time.Time
	Closed time.Time
	Cause  string // "" = clean end; otherwise the close-reason vocabulary
	TLS    *TLSInfo
	// ServeMode is how the flow was served: "mirror" | "tunnel" | "local"
	// | "reject"; "" when no serving hook decided.
	ServeMode string
	// Labels is the flow's labels, inherited from the hooks' Conn (see
	// hooks.Conn.SetLabel); nil when unlabeled.
	Labels map[string]string
}

// DefaultMaxChunks bounds the in-memory chunk record per connection.
const DefaultMaxChunks = 100_000

// Stream is the capture record of one connection. Append via Record, close
// via Finish; Chunks/Info are safe before and after Finish.
type Stream struct {
	mu       sync.Mutex
	info     CloseInfo
	buf      []Chunk // ring once full (bounded mode), plain slice otherwise
	limit    int     // max retained chunks
	head     int     // oldest retained element, when the ring has wrapped
	evicted  int
	finished bool
	bytes    bool // payload capture on (Registry.EnableBytes at Open)
	doneOnce sync.Once
	done     chan struct{}
}

// NewStream returns the record for a connection described by info (Opened
// is filled here). maxChunks <= 0 uses DefaultMaxChunks.
func NewStream(info CloseInfo, maxChunks int) *Stream {
	if maxChunks <= 0 {
		maxChunks = DefaultMaxChunks
	}
	info.Opened = time.Now()
	return &Stream{info: info, limit: maxChunks, done: make(chan struct{})}
}

// Record appends one chunk decision. It is a no-op after Finish. Once the
// buffer is full, new records overwrite the oldest (ring); every overwrite
// counts in Evicted.
func (s *Stream) Record(c Chunk) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return
	}
	if len(s.buf) < s.limit {
		s.buf = append(s.buf, c)
		return
	}
	// At the cap: overwrite the oldest (ring).
	s.buf[s.head] = c
	s.head = (s.head + 1) % len(s.buf)
	s.evicted++
}

// Chunks returns a snapshot of the retained chunk records, oldest first.
func (s *Stream) Chunks() []Chunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Chunk, 0, len(s.buf))
	if len(s.buf) == s.limit && s.head != 0 {
		// The ring wrapped: oldest is at head.
		for i := range s.buf {
			out = append(out, s.buf[(s.head+i)%len(s.buf)])
		}
		return out
	}
	out = append(out, s.buf...)
	return out
}

// Evicted reports how many earlier chunks a bounded record has dropped.
// Non-zero means the record is partial — loss is a number, never silent.
func (s *Stream) Evicted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

// BytesEnabled reports whether chunk records on this stream carry payload
// bytes (Registry.EnableBytes at Open). Set before the stream is
// published; stable for the stream's lifetime.
func (s *Stream) BytesEnabled() bool { return s.bytes }

// Finish closes the record with the connection's cause. Idempotent.
func (s *Stream) Finish(cause string) {
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return
	}
	s.info.Cause = cause
	s.info.Closed = time.Now()
	s.finished = true
	s.mu.Unlock()
	s.doneOnce.Do(func() { close(s.done) })
}

// Wait returns a channel closed when the record finished.
func (s *Stream) Wait() <-chan struct{} { return s.done }

// Info returns the metadata; Closed and Cause are zero/empty until Finish.
func (s *Stream) Info() CloseInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// SetTLS attaches the client-leg TLS outcome to the record.
func (s *Stream) SetTLS(ti *TLSInfo) {
	s.mu.Lock()
	s.info.TLS = ti
	s.mu.Unlock()
}

// SetServeMode records how the flow is served. Call once, before chunks
// flow.
func (s *Stream) SetServeMode(m string) {
	s.mu.Lock()
	s.info.ServeMode = m
	s.mu.Unlock()
}

// SetLabels attaches the flow labels to the record. Call once, before
// chunks flow.
func (s *Stream) SetLabels(m map[string]string) {
	s.mu.Lock()
	s.info.Labels = m
	s.mu.Unlock()
}

// Registry is the process-wide registry of connection records. The relay
// opens a stream per connection; the host sets OnConnection to receive each
// stream at connection open (before any chunk is recorded). Finished
// streams are kept for host reading until Evict runs.
type Registry struct {
	mu      sync.Mutex
	streams map[string]*Stream
	onOpen  func(*Stream)
	max     int
	bytes   bool // payload capture for streams opened while true
}

// NewRegistry returns an empty registry with DefaultMaxChunks.
func NewRegistry() *Registry {
	return &Registry{streams: make(map[string]*Stream), max: DefaultMaxChunks}
}

// SetMaxChunks bounds each record (see NewStream).
func (r *Registry) SetMaxChunks(n int) {
	r.mu.Lock()
	r.max = n
	r.mu.Unlock()
}

// EnableBytes turns on payload capture for streams opened after this
// call. Default off: records carry no payload and the record path pays
// only a bool check.
func (r *Registry) EnableBytes() {
	r.mu.Lock()
	r.bytes = true
	r.mu.Unlock()
}

// OnConnection sets the host callback. It is called synchronously when a
// connection's record is created; set it before connections flow.
func (r *Registry) OnConnection(fn func(*Stream)) {
	r.mu.Lock()
	r.onOpen = fn
	r.mu.Unlock()
}

// Open creates the record for a new connection and returns it. The
// registry's payload-capture flag is snapshotted onto the stream here.
func (r *Registry) Open(info CloseInfo) *Stream {
	r.mu.Lock()
	max := r.max
	bytesOn := r.bytes
	fn := r.onOpen
	r.mu.Unlock()
	s := NewStream(info, max)
	s.bytes = bytesOn
	r.mu.Lock()
	r.streams[info.ID] = s
	r.mu.Unlock()
	if fn != nil {
		fn(s)
	}
	return s
}

// Get returns the record for id, or nil.
func (r *Registry) Get(id string) *Stream {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[id]
}

// Evict removes finished records whose connection ended more than maxAge
// before now; live records are kept.
func (r *Registry) Evict(now time.Time, maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.streams {
		info := s.Info()
		if info.Closed.IsZero() || now.Sub(info.Closed) < maxAge {
			continue
		}
		delete(r.streams, id)
	}
}
