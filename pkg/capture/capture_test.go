package capture

import (
	"testing"
	"time"
)

func TestStreamRecordAndSnapshot(t *testing.T) {
	s := NewStream(CloseInfo{ID: "1-1", Kind: "plain_http", Client: "c", Dst: "d"}, 0)
	now := time.Now()
	s.Record(Chunk{Dir: DirC2S, TS: now, Len: 4, Decision: Forwarded})
	s.Record(Chunk{Dir: DirS2C, TS: now, Len: 2, Decision: Dropped, Reason: "policy"})
	got := s.Chunks()
	if len(got) != 2 || got[0].Len != 4 || got[1].Reason != "policy" {
		t.Fatalf("Chunks = %+v, want the two records in order", got)
	}
	if s.Evicted() != 0 {
		t.Errorf("Evicted = %d, want 0 (unbounded)", s.Evicted())
	}
	if info := s.Info(); info.ID != "1-1" || info.Opened.IsZero() {
		t.Errorf("Info = %+v, want the opened metadata", info)
	}
}

func TestStreamBoundedEviction(t *testing.T) {
	s := NewStream(CloseInfo{ID: "2"}, 3)
	for i := 0; i < 5; i++ {
		s.Record(Chunk{Len: i, Decision: Forwarded})
	}
	got := s.Chunks()
	if len(got) != 3 {
		t.Fatalf("Chunks len = %d, want the last 3", len(got))
	}
	for i, want := range []int{2, 3, 4} {
		if got[i].Len != want {
			t.Errorf("retained[%d].Len = %d, want %d (oldest evicted)", i, got[i].Len, want)
		}
	}
	if s.Evicted() != 2 {
		t.Errorf("Evicted = %d, want 2 (loss must be observable)", s.Evicted())
	}
}

func TestStreamFinish(t *testing.T) {
	s := NewStream(CloseInfo{ID: "3"}, 0)
	s.Record(Chunk{Decision: Forwarded})
	s.Finish("client gone")
	s.Record(Chunk{Decision: Dropped}) // must be ignored after Finish
	if len(s.Chunks()) != 1 {
		t.Errorf("post-Finish Record was retained: %d chunks", len(s.Chunks()))
	}
	select {
	case <-s.Wait():
	case <-time.After(time.Second):
		t.Fatal("Wait not closed after Finish")
	}
	info := s.Info()
	if info.Cause != "client gone" || info.Closed.IsZero() {
		t.Errorf("Info after Finish = %+v, want cause and closed time", info)
	}
	// Finish is idempotent.
	s.Finish("again")
	if s.Info().Cause != "client gone" {
		t.Error("second Finish overwrote the cause")
	}
}

func TestEnableBytesPopulatesPayload(t *testing.T) {
	r := NewRegistry()
	r.EnableBytes()
	st := r.Open(CloseInfo{ID: "b1"})
	if !st.BytesEnabled() {
		t.Fatal("BytesEnabled = false after EnableBytes")
	}
	if NewStream(CloseInfo{ID: "b2"}, 0).BytesEnabled() {
		t.Fatal("directly constructed streams must default to disabled")
	}
}

func TestBytesDisabledDefault(t *testing.T) {
	if NewRegistry().Open(CloseInfo{ID: "b3"}).BytesEnabled() {
		t.Fatal("default registry must be disabled")
	}
}

func TestRegistryOpenGetEvict(t *testing.T) {
	r := NewRegistry()
	var seen *Stream
	r.OnConnection(func(s *Stream) { seen = s })
	s := r.Open(CloseInfo{ID: "9", Kind: "tls"})
	if seen != s {
		t.Fatal("OnConnection was not called with the new stream")
	}
	if r.Get("9") != s || r.Get("nope") != nil {
		t.Error("Get by id misbehaves")
	}
	// Live streams survive eviction.
	r.Evict(time.Now(), time.Hour)
	if r.Get("9") != s {
		t.Fatal("live stream evicted")
	}
	s.Finish("")
	r.Evict(s.Info().Closed.Add(time.Hour+time.Second), time.Hour)
	if r.Get("9") != nil {
		t.Error("finished stream not evicted past maxAge")
	}
}
