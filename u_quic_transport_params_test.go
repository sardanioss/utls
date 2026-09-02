package tls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Extension 57 was the single extension this package recognised without being
// able to parse it, which meant a captured QUIC ClientHello could only be read
// under blunt mimicry. Blunt mimicry passes every unrecognised extension through
// unchecked, so one unmodelled extension switched off validation for all of
// them.
//
// These lock the three properties that removing that depends on.

// 1. It is a TLSExtensionWriter, which is what the parser tests for.
func TestQUICTransportParametersIsWritable(t *testing.T) {
	ext := ExtensionFromID(extensionQUICTransportParameters)
	if ext == nil {
		t.Fatal("extension 57 is not recognised at all")
	}
	if _, ok := ext.(TLSExtensionWriter); !ok {
		t.Fatal("extension 57 has no Write method, so a QUIC capture still cannot " +
			"be parsed without blunt mimicry")
	}
}

// 2. It round-trips byte for byte. A parameter model could not promise this:
// the body is varint-tagged values whose order and integer widths are the
// sender's choice, so re-marshalling can change the bytes without changing the
// meaning, and for a fingerprint the bytes are the meaning.
func TestQUICTransportParametersRoundTripsExactly(t *testing.T) {
	// A body with a redundantly-wide varint, which a re-encoder would shrink.
	body := []byte{0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x03, 0x02, 0x45, 0xc0, 0x09, 0x01, 0x03}

	var e QUICTransportParametersExtension
	n, err := e.Write(body)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(body) {
		t.Fatalf("Write consumed %d of %d bytes", n, len(body))
	}

	out := make([]byte, e.Len())
	if _, err := e.Read(out); err != nil && err.Error() != "EOF" {
		t.Fatalf("Read: %v", err)
	}
	if id := binary.BigEndian.Uint16(out[0:2]); id != extensionQUICTransportParameters {
		t.Errorf("wrote extension id %d, want %d", id, extensionQUICTransportParameters)
	}
	if l := int(binary.BigEndian.Uint16(out[2:4])); l != len(body) {
		t.Errorf("declared length %d, want %d", l, len(body))
	}
	if !bytes.Equal(out[4:], body) {
		t.Errorf("body changed across the round trip:\n  in:  %x\n  out: %x", body, out[4:])
	}
}

// 3. A hello carrying it now parses with blunt mimicry OFF, and the extension
// comes back as its own type rather than an opaque GenericExtension. That is
// what restores per-extension validation for the rest of a QUIC capture.
func TestQUICCaptureParsesWithoutBluntMimicry(t *testing.T) {
	var block []byte
	add := func(id uint16, body []byte) {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], id)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
		block = append(block, hdr[:]...)
		block = append(block, body...)
	}
	add(0x0a0a, nil)                        // GREASE
	add(0, []byte{0, 5, 0, 0, 2, 'h', 'i'}) // SNI
	add(extensionQUICTransportParameters, []byte{0x01, 0x02, 0x03})
	add(21, make([]byte, 4)) // padding

	var spec ClientHelloSpec
	if err := spec.ReadTLSExtensions(block, false, false); err != nil {
		t.Fatalf("parsing a QUIC hello with blunt mimicry off: %v\n"+
			"this is exactly what forced allow_blunt_mimicry on every QUIC capture", err)
	}

	var found bool
	for _, e := range spec.Extensions {
		if q, ok := e.(*QUICTransportParametersExtension); ok {
			found = true
			if !bytes.Equal(q.RawData, []byte{0x01, 0x02, 0x03}) {
				t.Errorf("captured body not retained: %x", q.RawData)
			}
		}
		if g, ok := e.(*GenericExtension); ok && g.Id == extensionQUICTransportParameters {
			t.Error("extension 57 still came back as an opaque GenericExtension")
		}
	}
	if !found {
		t.Error("extension 57 did not parse into its own type")
	}
}
