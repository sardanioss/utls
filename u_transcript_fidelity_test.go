package tls

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestCertificateMsgTLS13KeepsOriginalForTranscript pins the fix for a TLS 1.3
// handshake failure against servers that staple OCSP or embed SCTs in the
// Certificate message.
//
// readServerCertificate reads that message without hashing it, so it can first
// decide whether the message is a CompressedCertificate, and hashes it
// afterwards through transcriptMsg. transcriptMsg re-marshals any message that
// does not keep its original bytes, and certificateMsgTLS13.marshal drops the
// OCSP staple and the SCTs unless ocspStapling and scts are set, which
// unmarshal never does.
//
// The re-marshalled message is therefore shorter than the one on the wire, the
// client transcript diverges from the server transcript, and the server
// CertificateVerify fails to verify with
//
//	tls: invalid signature by the server certificate: crypto/rsa: verification error
//
// Keeping the original bytes is what makes the transcript faithful.
func TestCertificateMsgTLS13KeepsOriginalForTranscript(t *testing.T) {
	stapled := &certificateMsgTLS13{
		certificate: Certificate{
			Certificate:                 [][]byte{[]byte("leaf-certificate-bytes")},
			OCSPStaple:                  []byte("ocsp-staple"),
			SignedCertificateTimestamps: [][]byte{[]byte("sct-one"), []byte("sct-two")},
		},
		ocspStapling: true,
		scts:         true,
	}

	wire, err := stapled.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed certificateMsgTLS13
	if !parsed.unmarshal(wire) {
		t.Fatal("unmarshal rejected a message it had just produced")
	}

	if !bytes.Equal(parsed.originalBytes(), wire) {
		t.Fatal("the parsed message does not carry the bytes it was parsed from")
	}

	// Without the original bytes the transcript would be fed this instead, and
	// it is a different message: the staple and the timestamps are gone.
	remarshalled, err := parsed.marshal()
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if bytes.Equal(remarshalled, wire) {
		t.Skip("re-marshalling now round-trips; the original bytes are belt and braces")
	}

	got := sha256.New()
	if err := transcriptMsg(&parsed, got); err != nil {
		t.Fatalf("transcriptMsg: %v", err)
	}

	want := sha256.New()
	want.Write(wire)

	if !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
		t.Fatal("the transcript hashed a re-marshalled message rather than the bytes the peer sent")
	}
}
