package tls

import (
	"net"
	"testing"
)

// Chrome greases signature_algorithms from version 152.
//
// BoringSSL, ext_sigalgs_add_clienthello:
//
//	// Add a fake signature algorithm. See RFC 8701.
//	if (hs->ssl->ctx->grease_sigalgs_enabled &&
//	    !CBB_add_u16(&sigalgs_cbb,
//	                 ssl_get_grease_value(hs, ssl_grease_signature_algorithm))) {
//	  return false;
//	}
//	if (!tls12_add_verify_sigalgs(hs, &sigalgs_cbb) || ...
//
// so the fake algorithm is written before the real list.

// greaseSigalgSpec is Chrome 152 shaped over TCP: a GREASE placeholder ahead of
// the ML-DSA trio and the eight classic algorithms.
func greaseSigalgSpec() *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{GREASE_PLACEHOLDER, TLS_AES_128_GCM_SHA256},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []SignatureScheme{
					SignatureScheme(GREASE_PLACEHOLDER),
					0x0904, 0x0905, 0x0906,
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				},
			},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&UtlsGREASEExtension{},
		},
	}
}

func applySigalgSpec(t *testing.T) *UConn {
	t.Helper()
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(greaseSigalgSpec()); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uconn.ApplyConfig(); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	return uconn
}

func sigalgsOf(t *testing.T, uconn *UConn) []SignatureScheme {
	t.Helper()
	for _, ext := range uconn.Extensions {
		if sa, ok := ext.(*SignatureAlgorithmsExtension); ok {
			return sa.SupportedSignatureAlgorithms
		}
	}
	t.Fatal("no signature_algorithms extension after ApplyPreset")
	return nil
}

// The placeholder is replaced by a real GREASE value, in place, so the
// preset decides where it sits and BoringSSL's leading position is just what
// the preset writes.
func TestSigalgGREASEIsSubstituted(t *testing.T) {
	uconn := applySigalgSpec(t)
	got := sigalgsOf(t, uconn)

	if len(got) != 12 {
		t.Fatalf("signature_algorithms has %d entries, want 12", len(got))
	}
	if got[0] == SignatureScheme(GREASE_PLACEHOLDER) {
		t.Fatal("the placeholder 0x0a0a survived ApplyPreset; every connection " +
			"would advertise the same fake algorithm")
	}
	if !isGREASEUint16(uint16(got[0])) {
		t.Fatalf("first signature algorithm is %#04x, which is not a GREASE value", got[0])
	}
	for i, sa := range got[1:] {
		if isGREASEUint16(uint16(sa)) {
			t.Errorf("entry %d is a second GREASE value %#04x; BoringSSL adds exactly one", i+1, sa)
		}
	}
}

// The value is drawn per connection and covers the whole GREASE space.
//
// It is also independent of the other GREASE values, because BoringSSL keys
// each one off its own seed byte. That independence is what the seed array
// off-by-one used to make impossible: the array was sized by
// ssl_grease_last_index, an INDEX, so the last slot did not exist.
func TestSigalgGREASEVariesAndIsIndependent(t *testing.T) {
	const runs = 300
	seen := map[uint16]int{}
	matchedCipher := 0

	for i := 0; i < runs; i++ {
		uconn := applySigalgSpec(t)
		v := uint16(sigalgsOf(t, uconn)[0])
		if v&0x0f0f != 0x0a0a {
			t.Fatalf("GREASE value %#04x is not of the form 0x?a?a", v)
		}
		seen[v]++
		if v == uconn.HandshakeState.Hello.CipherSuites[0] {
			matchedCipher++
		}
	}

	// Sixteen values are possible and 300 draws hit essentially all of them.
	if len(seen) < 14 {
		t.Errorf("%d draws produced only %d distinct GREASE values, want close to 16",
			runs, len(seen))
	}
	// One in sixteen by chance, so about 19 of 300. Far above that means the
	// sigalg value is being taken from another index's seed byte.
	if matchedCipher > runs/5 {
		t.Errorf("the signature-algorithm GREASE equalled the cipher GREASE %d "+
			"times in %d; each index has its own seed byte, so this should be "+
			"about one in sixteen", matchedCipher, runs)
	}
}

// The GREASE value goes on the wire and stays off the Hello.
//
// BoringSSL advertises a fake algorithm and never selects it. Letting Go's
// certificate logic see one as a candidate would be a bug rather than a
// fingerprint, so the Hello carries only the real algorithms.
func TestSigalgGREASEStaysOffTheHello(t *testing.T) {
	uconn := applySigalgSpec(t)

	onTheWire := sigalgsOf(t, uconn)
	if !isGREASEUint16(uint16(onTheWire[0])) {
		t.Fatal("no GREASE value on the wire to begin with")
	}

	hello := uconn.HandshakeState.Hello.SupportedSignatureAlgorithms
	if len(hello) != len(onTheWire)-1 {
		t.Fatalf("the Hello carries %d algorithms and the wire %d; want exactly "+
			"one fewer, the GREASE entry", len(hello), len(onTheWire))
	}
	for i, sa := range hello {
		if isGREASEUint16(uint16(sa)) {
			t.Errorf("Hello entry %d is the GREASE value %#04x; Go's certificate "+
				"logic would treat it as a candidate", i, sa)
		}
	}
	// And the real ones survive in order.
	for i, sa := range onTheWire[1:] {
		if hello[i] != sa {
			t.Errorf("Hello entry %d is %#04x, want %#04x", i, hello[i], sa)
		}
	}
}

// A spec with no placeholder is untouched, so no existing preset starts
// greasing its signature algorithms by accident.
func TestSigalgWithoutPlaceholderIsUnchanged(t *testing.T) {
	spec := greaseSigalgSpec()
	for _, ext := range spec.Extensions {
		if sa, ok := ext.(*SignatureAlgorithmsExtension); ok {
			sa.SupportedSignatureAlgorithms = sa.SupportedSignatureAlgorithms[1:]
		}
	}
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uconn.ApplyConfig(); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	got := sigalgsOf(t, uconn)
	if len(got) != 11 {
		t.Fatalf("got %d algorithms, want the 11 the spec listed", len(got))
	}
	for i, sa := range got {
		if isGREASEUint16(uint16(sa)) {
			t.Errorf("entry %d became a GREASE value %#04x without a placeholder", i, sa)
		}
	}
	if n := len(uconn.HandshakeState.Hello.SupportedSignatureAlgorithms); n != 11 {
		t.Errorf("the Hello carries %d algorithms, want 11; the ungreased path "+
			"should not be copying or filtering", n)
	}
}

// The seed array holds every index BoringSSL defines, including the last.
//
// BoringSSL sizes its own as grease_seed[ssl_grease_last_index + 1]. Sizing by
// the index instead silently dropped the final slot, which is why
// ssl_grease_ticket_extension was unusable here long before the two new
// indices were added.
func TestGREASESeedHoldsEveryIndex(t *testing.T) {
	if ssl_grease_seed_len != ssl_grease_last_index+1 {
		t.Fatalf("ssl_grease_seed_len = %d, want ssl_grease_last_index + 1 = %d",
			ssl_grease_seed_len, ssl_grease_last_index+1)
	}
	if ssl_grease_signature_algorithm != ssl_grease_last_index {
		t.Fatalf("ssl_grease_signature_algorithm = %d but ssl_grease_last_index = %d; "+
			"BoringSSL defines them equal", ssl_grease_signature_algorithm, ssl_grease_last_index)
	}
	var seed [ssl_grease_seed_len]uint16
	for i := range seed {
		seed[i] = uint16(i * 0x11)
	}
	// Every index is addressable, the last one included. This panics rather
	// than fails if the array is short, which is the point.
	for i := 0; i <= ssl_grease_last_index; i++ {
		if v := GetBoringGREASEValue(seed, i); v&0x0f0f != 0x0a0a {
			t.Errorf("index %d produced %#04x, which is not a GREASE value", i, v)
		}
	}
}
