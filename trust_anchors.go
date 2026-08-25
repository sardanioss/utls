package tls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// TrustAnchorsExtension implements trust_anchors (0xCA34), from
// draft-ietf-tls-trust-anchor-ids. Chrome ships it from version 152.
//
// The wire shape is BoringSSL's ext_trust_anchors_add_clienthello:
//
//	CBB_add_u16(out_compressible, TLSEXT_TYPE_trust_anchors)
//	CBB_add_u16_length_prefixed(out_compressible, &contents)
//	CBB_add_u16_length_prefixed(&contents, &list)
//	CBB_add_bytes(&list, hs->config->requested_trust_anchors->data(), ...)
//
// so: type, extension length, a u16 list length, then the list. Each entry in
// the list is a single-byte length followed by that many bytes of trust anchor
// identifier, which is an encoded relative object identifier.
//
// Note that BoringSSL copies a caller-supplied blob verbatim, which means the
// ORDER is decided above BoringSSL, by the browser. Two captures of the same
// Chrome build, one over TCP and one over QUIC, carry an identical set of
// identifiers in a different order, so the order is not fixed. Shuffle
// reproduces that; see the comment on the field.
type TrustAnchorsExtension struct {
	// TrustAnchors is the list of trust anchor identifiers, in canonical
	// order. Each entry is an encoded relative object identifier and must be
	// at most 255 bytes.
	TrustAnchors [][]byte

	// Shuffle permutes the list once per connection.
	//
	// The order is not part of any published fingerprint hash, but it is
	// plainly visible in the extension body, and a client that emits one fixed
	// order where the browser varies it is distinguishable across two
	// connections without any statistics at all. That is the same shape as the
	// QUIC transport-parameter order.
	Shuffle bool

	// emitOrder is the permutation used for this connection, chosen in
	// writeToUConn. Nil means emit TrustAnchors as given.
	emitOrder [][]byte
}

func (e *TrustAnchorsExtension) list() [][]byte {
	if e.emitOrder != nil {
		return e.emitOrder
	}
	return e.TrustAnchors
}

func (e *TrustAnchorsExtension) writeToUConn(uc *UConn) error {
	if !e.Shuffle || len(e.TrustAnchors) < 2 {
		e.emitOrder = nil
		return nil
	}
	// A fresh slice per connection rather than shuffling in place, so a spec
	// shared between connections is not mutated underneath one of them.
	out := make([][]byte, len(e.TrustAnchors))
	copy(out, e.TrustAnchors)
	for i := len(out) - 1; i > 0; i-- {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			e.emitOrder = nil
			return nil
		}
		j := int(binary.BigEndian.Uint64(b[:]) % uint64(i+1))
		out[i], out[j] = out[j], out[i]
	}
	e.emitOrder = out
	return nil
}

func (e *TrustAnchorsExtension) Len() int {
	n := 2 + 2 + 2
	for _, ta := range e.TrustAnchors {
		n += 1 + len(ta)
	}
	return n
}

func (e *TrustAnchorsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// Both lengths on the wire are u16. A list built by Write cannot exceed
	// that, because it was parsed out of a u16-prefixed field, but a caller
	// may set TrustAnchors directly, and silently truncating there would emit
	// a well-formed extension carrying the wrong bytes.
	if n := e.Len() - 6; n > 0xffff-2 {
		return 0, errors.New("tls: trust_anchors list does not fit a uint16 length")
	}
	binary.BigEndian.PutUint16(b[0:], utlsExtensionTrustAnchors)

	body := b[6:]
	listLen := 0
	for _, ta := range e.list() {
		body[0] = byte(len(ta))
		copy(body[1:], ta)
		body = body[1+len(ta):]
		listLen += 1 + len(ta)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(listLen+2)) // extension length
	binary.BigEndian.PutUint16(b[4:], uint16(listLen))   // list length
	return e.Len(), io.EOF
}

func (e *TrustAnchorsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) {
		return 0, errors.New("unable to read trust_anchors extension data")
	}
	var anchors [][]byte
	for !list.Empty() {
		var ta cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&ta) || ta.Empty() {
			return 0, errors.New("unable to read a trust_anchors entry")
		}
		anchors = append(anchors, append([]byte(nil), ta...))
	}
	e.TrustAnchors = anchors
	return fullLen, nil
}
