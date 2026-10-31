// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// A TLS 1.3 Certificate goes into the transcript as the server sent it. Servers may put a
// leaf's SCTs before its OCSP staple (payments.braintree-api.com does), and certificates
// after the leaf may carry extensions of their own; re-marshalling the parsed message would
// change both, and the client would then reject the server's CertificateVerify.
func TestCertificateMsgTLS13TranscriptKeepsServerBytes(t *testing.T) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("leaf")) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(extensionSCT)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("sct")) })
					})
				})
				b.AddUint16(extensionStatusRequest)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(statusTypeOCSP)
					b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("ocsp")) })
				})
			})
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("intermediate")) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(extensionSCT)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("sct")) })
					})
				})
			})
		})
	})
	sent := b.BytesOrPanic()

	var msg certificateMsgTLS13
	if !msg.unmarshal(sent) {
		t.Fatal("the Certificate message did not parse")
	}
	got, want := sha256.New(), sha256.New()
	if err := transcriptMsg(&msg, got); err != nil {
		t.Fatal(err)
	}
	want.Write(sent)
	if !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
		t.Fatal("the transcript holds a re-marshalled Certificate, not the one the server sent")
	}
}
