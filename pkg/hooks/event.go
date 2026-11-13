package hooks

// EventKind classifies the lifecycle and pressure events the relay
// delivers to EventObservers in-band.
type EventKind int

const (
	// HoldWatermark: a direction's hold buffer crossed its high-water mark.
	HoldWatermark EventKind = iota
	// UpstreamConnectFailed: the mirror/tunnel dial to the upstream failed.
	UpstreamConnectFailed
	// UpstreamClose: the upstream leg ended (per-leg; see Event).
	UpstreamClose
	// ClientClose: the client leg ended (per-leg; see Event).
	ClientClose
	// TLSAlert: a TLS alert (e.g. an mTLS rejection) ended the flow.
	TLSAlert
	// Drain: the flow ended while the proxy was draining (Shutdown running).
	Drain
)

// String returns the kind's record name, e.g. "upstream_close".
func (k EventKind) String() string {
	switch k {
	case HoldWatermark:
		return "hold_watermark"
	case UpstreamConnectFailed:
		return "upstream_connect_failed"
	case UpstreamClose:
		return "upstream_close"
	case ClientClose:
		return "client_close"
	case TLSAlert:
		return "tls_alert"
	case Drain:
		return "drain"
	default:
		return "event"
	}
}

// Event is one lifecycle or pressure notification. Delivered in-band and
// synchronously to every matched hook that implements EventObserver.
// UpstreamClose/ClientClose fire per leg at relay end — both legs end, both
// events fire; Detail carries the leg's end error ("" when clean).
type Event struct {
	Kind   EventKind
	Dir    Dir    // the direction the event concerns
	Detail string // e.g. the dial error or leg end error, "" when not applicable
}

// EventObserver receives the relay's typed lifecycle and pressure events.
// OnEvent is synchronous: a hook that blocks in it delays the flow (same
// contract as OnData).
type EventObserver interface {
	OnEvent(c *Conn, e Event)
}

// Emit delivers e to every matched EventObserver hook. The relay calls it
// for lifecycle events; it is nil-safe. Synchronous: a hook that blocks in
// OnEvent delays the flow (same contract as OnData).
func (p *Pipe) Emit(e Event) {
	if p == nil {
		return
	}
	for _, h := range p.hooks {
		if o, ok := h.(EventObserver); ok {
			o.OnEvent(p.conn, e)
		}
	}
}
