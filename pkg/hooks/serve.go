package hooks

import (
	"errors"
	"io"
)

// ServeMode is how a flow is served, decided per flow at establishment by
// the first hook in the chain that implements Serving.
type ServeMode int

const (
	// ServeMirror dials the real upstream and mirrors both directions.
	// The default when no hook implements Serving — the historical behavior.
	ServeMirror ServeMode = iota
	// ServeTunnel relays the flow verbatim (prefix included) to the real
	// upstream with no TLS interception: no leaf is minted and the client
	// leg is not terminated. For plain and raw flows it is identical to
	// ServeMirror.
	ServeTunnel
	// ServeLocal serves the flow with no upstream: the client leg stays
	// healthy on hook-injected bytes indefinitely, and the c2s leg is
	// delivered to the consumer-provided leg carried by the decision.
	// The consumer reads and writes that leg at any time.
	ServeLocal
	// ServeReject refuses the flow at establishment, like a Close verdict
	// at open; the decision's Reason is the close reason.
	ServeReject
)

// String returns the mode's serve_mode record name: "mirror", "tunnel",
// "local", or "reject".
func (m ServeMode) String() string {
	switch m {
	case ServeMirror:
		return "mirror"
	case ServeTunnel:
		return "tunnel"
	case ServeLocal:
		return "local"
	case ServeReject:
		return "reject"
	default:
		return "mode"
	}
}

// ServeDecision is the outcome of a flow's establishment decision.
type ServeDecision struct {
	// Mode is how the flow is served.
	Mode ServeMode
	// Local is the consumer-provided upstream leg, required when
	// Mode == ServeLocal. prox adapts it to its conn plumbing and closes
	// it with the connection.
	Local io.ReadWriteCloser
	// Reason is the close reason when Mode == ServeReject.
	Reason string
}

// Serving is implemented by a hook that decides how a flow is served.
// Serve is called once, after the OnOpen chain admitted the connection and
// before any upstream work (dial, mint, or local-leg wiring). The first
// hook in chain order that implements Serving decides; later hooks are
// not asked. A non-nil error, or ServeLocal without a Local leg, turns the
// decision into ServeReject with the error as the close reason. Synchronous
// contract, as OnOpen: a hook that blocks in Serve delays the flow.
type Serving interface {
	Serve(c *Conn) (ServeDecision, error)
}

// ErrLocalWithoutLeg is the reject reason for a ServeLocal decision that
// carries no leg.
var ErrLocalWithoutLeg = errors.New("hooks: ServeLocal decision without a leg")

// Serve runs the establishment-decision pass and returns the flow's serve
// decision. Call it after Open, only when Open admitted the connection.
// A nil Pipe returns the Mirror decision.
func (p *Pipe) Serve() ServeDecision {
	dec := ServeDecision{Mode: ServeMirror}
	if p == nil {
		return dec
	}
	for _, h := range p.hooks {
		s, ok := h.(Serving)
		if !ok {
			continue
		}
		d, err := s.Serve(p.conn)
		if err != nil {
			d = ServeDecision{Mode: ServeReject, Reason: err.Error()}
		}
		if d.Mode == ServeLocal && d.Local == nil {
			d = ServeDecision{Mode: ServeReject, Reason: ErrLocalWithoutLeg.Error()}
		}
		dec = d
		break
	}
	return dec
}
