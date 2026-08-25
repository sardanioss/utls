package tls

import (
	"encoding/hex"
	"io"
	"testing"
)

// The trust_anchors payload from a real Chrome 152 ClientHello over TCP:
// 204 bytes of list holding 32 identifiers across three issuer arcs.
const chrome152TrustAnchorsTCP = "00cc0582df13021308839a648c9b2d010d0582df1302060582df13020d08839a648c9b2d011204d6" +
	"79090304d679090c04d679090f08839a648c9b2d010c04d679090b08839a648c9b2d010704d67909" +
	"050582df13020e04d679090808839a648c9b2d010804d679090d04d679090108839a648c9b2d010a" +
	"04d679090904d679090608839a648c9b2d010b04d679090e0582df13020108839a648c9b2d010905" +
	"82df13021404d67909020582df13021204d679090a0582df13020f08839a648c9b2d011304d67909" +
	"0704d6790904"

// The same extension from the same Chrome build over QUIC: an identical set of
// identifiers in a different order.
const chrome152TrustAnchorsQUIC = "00cc04d679090c08839a648c9b2d010b08839a648c9b2d010a04d679090204d679090e0582df1302" +
	"0104d679090a0582df13021404d679090708839a648c9b2d010804d679090608839a648c9b2d0107" +
	"04d679090108839a648c9b2d010c04d679090908839a648c9b2d010d04d67909080582df13021204" +
	"d679090508839a648c9b2d01120582df13021304d679090b0582df13020608839a648c9b2d011305" +
	"82df13020e04d679090d0582df13020f04d67909030582df13020d04d679090f08839a648c9b2d01" +
	"0904d6790904"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

// A captured extension body must parse and re-emit byte for byte, or a raw
// Chrome hello cannot round-trip through the Fingerprinter.
func TestTrustAnchorsRoundTrip(t *testing.T) {
	body := mustHex(t, chrome152TrustAnchorsTCP)

	var e TrustAnchorsExtension
	n, err := e.Write(body)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(body) {
		t.Fatalf("Write consumed %d of %d bytes", n, len(body))
	}
	if len(e.TrustAnchors) != 32 {
		t.Fatalf("parsed %d identifiers, want 32", len(e.TrustAnchors))
	}

	out := make([]byte, e.Len())
	if _, err := e.Read(out); err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	// Read emits the full extension: type, length, then the body.
	if got, want := hex.EncodeToString(out[:2]), "ca34"; got != want {
		t.Fatalf("extension type = %s, want %s", got, want)
	}
	if got := hex.EncodeToString(out[4:]); got != hex.EncodeToString(body) {
		t.Fatalf("body did not round-trip\n got %s\nwant %s", got, hex.EncodeToString(body))
	}
	// The extension length covers the list plus its own 2-byte length.
	if got, want := int(out[2])<<8|int(out[3]), len(body); got != want {
		t.Fatalf("extension length = %d, want %d", got, want)
	}
}

// The same identifiers appear in both of Chrome's captures, in a different
// order. That is what the shuffle reproduces, so it is worth pinning that the
// SET is the thing that is stable.
func TestTrustAnchorsSameSetDifferentOrder(t *testing.T) {
	var tcp, quic TrustAnchorsExtension
	if _, err := tcp.Write(mustHex(t, chrome152TrustAnchorsTCP)); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	if _, err := quic.Write(mustHex(t, chrome152TrustAnchorsQUIC)); err != nil {
		t.Fatalf("quic: %v", err)
	}
	set := func(e TrustAnchorsExtension) map[string]int {
		m := map[string]int{}
		for _, ta := range e.TrustAnchors {
			m[hex.EncodeToString(ta)]++
		}
		return m
	}
	a, b := set(tcp), set(quic)
	if len(a) != len(b) {
		t.Fatalf("distinct identifiers: tcp=%d quic=%d", len(a), len(b))
	}
	for k, v := range a {
		if b[k] != v {
			t.Errorf("identifier %s appears %d times over TCP and %d over QUIC", k, v, b[k])
		}
	}
}

// Shuffling must permute and must not lose, duplicate or corrupt an entry.
func TestTrustAnchorsShufflePreservesTheSet(t *testing.T) {
	var base TrustAnchorsExtension
	if _, err := base.Write(mustHex(t, chrome152TrustAnchorsTCP)); err != nil {
		t.Fatalf("write: %v", err)
	}

	canonical := map[string]int{}
	for _, ta := range base.TrustAnchors {
		canonical[hex.EncodeToString(ta)]++
	}

	orders := map[string]bool{}
	for i := 0; i < 200; i++ {
		e := TrustAnchorsExtension{TrustAnchors: base.TrustAnchors, Shuffle: true}
		if err := e.writeToUConn(nil); err != nil {
			t.Fatalf("writeToUConn: %v", err)
		}
		out := make([]byte, e.Len())
		if _, err := e.Read(out); err != nil && err != io.EOF {
			t.Fatalf("Read: %v", err)
		}
		var back TrustAnchorsExtension
		if _, err := back.Write(out[4:]); err != nil {
			t.Fatalf("reparse: %v", err)
		}
		got := map[string]int{}
		var order string
		for _, ta := range back.TrustAnchors {
			got[hex.EncodeToString(ta)]++
			order += hex.EncodeToString(ta) + ","
		}
		if len(got) != len(canonical) {
			t.Fatalf("shuffle changed the identifier count: %d vs %d", len(got), len(canonical))
		}
		for k, v := range canonical {
			if got[k] != v {
				t.Fatalf("shuffle lost or duplicated %s", k)
			}
		}
		orders[order] = true
	}
	if len(orders) < 100 {
		t.Errorf("200 shuffles produced only %d distinct orders", len(orders))
	}

	// And with Shuffle off, the order is exactly as configured.
	e := TrustAnchorsExtension{TrustAnchors: base.TrustAnchors}
	if err := e.writeToUConn(nil); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, e.Len())
	e.Read(out)
	if hex.EncodeToString(out[4:]) != chrome152TrustAnchorsTCP {
		t.Error("with Shuffle off the emitted order is not the configured one")
	}
}
