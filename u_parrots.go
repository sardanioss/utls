// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/mlkem"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"strconv"

	"github.com/sardanioss/utls/dicttls"
)

var ErrUnknownClientHelloID = errors.New("tls: unknown ClientHelloID")

// UTLSIdToSpec converts a ClientHelloID to a corresponding ClientHelloSpec.
//
// Exported internal function utlsIdToSpec per request.
func UTLSIdToSpec(id ClientHelloID) (ClientHelloSpec, error) {
	return utlsIdToSpec(id)
}

// UTLSIdToSpecWithSeed returns a ClientHelloSpec with extensions shuffled using a specific seed.
// This ensures consistent extension order within a session while appearing random across sessions.
// The seed should be generated once per session and reused for all connections in that session.
func UTLSIdToSpecWithSeed(id ClientHelloID, seed int64) (ClientHelloSpec, error) {
	spec, err := utlsIdToSpec(id)
	if err != nil {
		return spec, err
	}

	// Apply the seeded shuffle, but ONLY to clients that really permute.
	//
	// This is the SECOND shuffle for a Chrome parrot: utlsIdToSpec already
	// shuffled the literal with fresh randomness on the way out.
	//
	// The comment here used to say this one buys stability within a session.
	// It does not, and cannot: the literal is shuffled with fresh randomness
	// before the seed is ever applied, so shuffling that by a fixed seed still
	// lands somewhere new. Measured, same seed twice, two different orders.
	//
	// That is fine, because per-connection is what the browser does. BoringSSL
	// keeps the permutation on the handshake, not on the context:
	//
	//	// extension_permutation is the permutation to apply to ClientHello
	//	// extensions. It maps indices into the `kExtensions` table into other
	//	// indices.
	//	Array<uint8_t> extension_permutation;   // in SSL_HANDSHAKE
	//
	//	bool ssl_setup_extension_permutation(SSL_HANDSHAKE *hs);
	//
	// so a Chrome profile draws a fresh order for every connection rather than
	// once per launch. Do not "fix" this into a per-session constant.
	//
	// It used to run for EVERY ClientHelloID. Extension permutation is a
	// Chromium behaviour: BoringSSL only shuffles when the caller sets
	// SSL_set_permute_extensions, which Chrome does and Apple's stack has no
	// equivalent of. Every literal that shuffles itself in this file is a
	// Chrome parrot; no Safari, iOS or Firefox parrot does. So a Safari-family
	// spec was being permuted here and nowhere else, which gave it a different
	// JA3 on every session where the real browser has exactly one.
	//
	// Measured against a real CriOS/151 capture: the browser sent
	//
	//	0-23-65281-10-11-16-5-13-18-51-45-43-27
	//
	// which is this file's canonical Safari 18 order, entry for entry, while
	// two of our own connections produced two different sequences. Thirteen
	// movable extensions is 6.2e9 orders, so a JA3 allowlist never matches and
	// two connections show the order moving with no statistics needed.
	if permutesExtensions(id) {
		spec.Extensions = ShuffleChromeTLSExtensionsWithSeed(spec.Extensions, seed)
	}

	return spec, nil
}

// permutesExtensions reports whether a client shuffles its ClientHello
// extensions, which is a Chromium behaviour rather than a general one.
//
// Chromium-based clients permute. Everything else keeps the canonical order
// its parrot declares. Anything unrecognised keeps permuting, because that is
// the previous behaviour and silently pinning an order is the worse mistake of
// the two: a pinned order that should move is invisible until someone captures
// the real client, while a moving order that should be pinned at least matches
// what this function did before.
func permutesExtensions(id ClientHelloID) bool {
	switch id.Client {
	case helloChrome, helloEdge, hello360, helloQQ:
		// Chromium, so BoringSSL with permutation enabled.
		return true
	case helloRandomized, helloRandomizedALPN, helloRandomizedNoALPN:
		// Randomised by construction; pinning them would defeat the point.
		return true
	case helloFirefox, helloSafari, helloIOS, helloAndroid, helloGolang:
		// NSS, Apple's stack, Conscrypt and Go respectively. None of them
		// permutes: BoringSSL's shuffle is opt-in and only Chromium opts in,
		// so Conscrypt does not either despite sharing the library.
		return false
	default:
		return true
	}
}

func utlsIdToSpec(id ClientHelloID) (ClientHelloSpec, error) {
	switch id {
	case HelloChrome_58, HelloChrome_62:
		return ClientHelloSpec{
			TLSVersMax: VersionTLS12,
			TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{compressionNone},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&SessionTicketExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1},
				},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&FakeChannelIDExtension{},
				&SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}},
				&SupportedCurvesExtension{[]CurveID{CurveID(GREASE_PLACEHOLDER),
					X25519, CurveP256, CurveP384}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
			GetSessionID: sha256.Sum256,
		}, nil
	case HelloChrome_70:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&SessionTicketExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&FakeChannelIDExtension{},
				&SupportedPointsExtension{SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10}},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{CertCompressionBrotli}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_72:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_83:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_87:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_96:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_100, HelloChrome_102:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_106_Shuffle:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement
	case HelloChrome_115_PQ:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	// Chrome ECH
	case HelloChrome_120:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement and ECH
	case HelloChrome_120_PQ:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{}, // PSK must be last extension for TLS 1.3 session resumption
			}),
		}, nil
	case HelloChrome_131:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_133:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	// Chrome 143 Windows - Fixed extension order matching real Chrome on Windows
	// Captured from real Chrome 143.0.0.0 on Windows 10
	// JA3: 9ee94565f2dd4d5572fd2576b18a21f0
	case HelloChrome_143_Windows:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome extension order with shuffling (Chrome shuffles extensions since v110)
			// GREASE extensions stay at boundaries, others are shuffled
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&StatusRequestExtension{},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				&SNIExtension{},
				&SCTExtension{},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				BoringGREASEECH(),
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SessionTicketExtension{},
				&ExtendedMasterSecretExtension{},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&UtlsGREASEExtension{},
			}),
		}, nil
	// Chrome 143 Linux - extension order with shuffling (Chrome shuffles since v110)
	case HelloChrome_143_Linux:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome extension order with shuffling (Chrome shuffles extensions since v110)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&StatusRequestExtension{},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				&SNIExtension{},
				&SCTExtension{},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				BoringGREASEECH(),
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SessionTicketExtension{},
				&ExtendedMasterSecretExtension{},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&UtlsGREASEExtension{},
			}),
		}, nil
	// Chrome 143 macOS - extension order with shuffling (Chrome shuffles since v110)
	case HelloChrome_143_macOS:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome extension order with shuffling (Chrome shuffles extensions since v110)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&StatusRequestExtension{},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				&SNIExtension{},
				&SCTExtension{},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				BoringGREASEECH(),
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SessionTicketExtension{},
				&ExtendedMasterSecretExtension{},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&UtlsGREASEExtension{},
			}),
		}, nil

	// Chrome 143 QUIC - Specific preset for HTTP/3 QUIC connections
	// Captured from real Chrome 143.0.0.0 QUIC connection
	// Key differences from TCP: No legacy TLS 1.2 extensions, different extension order
	// Note: quic_transport_parameters (57) is added by the QUIC layer, not here
	case HelloChrome_143_QUIC:
		// Chrome 143 QUIC fingerprint - matches real Chrome production
		// Includes X25519MLKEM768 (post-quantum hybrid) for key exchange
		// EXACT order from Chrome QUIC capture - NO shuffling for QUIC
		// NOTE: Chrome QUIC does NOT include GREASE in TLS extensions (only in transport params)
		return ClientHelloSpec{
			CipherSuites: []uint16{
				// Chrome QUIC uses only TLS 1.3 ciphers
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome QUIC extension order - EXACT order from real Chrome capture
			// Order: [17613, 45, 65037, 10, 16, 43, 0, 13, 27, 57, 51]
			Extensions: []TLSExtension{
				// application_settings (17613)
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h3"}},
				// psk_key_exchange_modes (45)
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				// encrypted_client_hello (65037) - GREASE ECH
				BoringGREASEECH(),
				// supported_groups (10) - Chrome QUIC order (no GREASE)
				&SupportedCurvesExtension{[]CurveID{
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				// application_layer_protocol_negotiation (16)
				&ALPNExtension{AlpnProtocols: []string{"h3"}},
				// supported_versions (43) - only TLS 1.3
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
				}},
				// server_name (0)
				&SNIExtension{},
				// signature_algorithms (13) - includes PKCS1WithSHA1
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1, // Chrome includes this
				}},
				// compress_certificate (27)
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				// quic_transport_parameters (57)
				&QUICTransportParametersExtension{},
				// key_share (51) - PQ hybrid + X25519 (no GREASE)
				&KeyShareExtension{[]KeyShare{
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
			},
		}, nil

	// Chrome 133 with PSK for session resumption
	case HelloChrome_133_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{}, // PSK must be last extension
			}),
		}, nil

	// Chrome 143 Windows with PSK for session resumption
	case HelloChrome_143_Windows_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome extension order with shuffling + PSK at end (Chrome shuffles since v110)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				BoringGREASEECH(),
				&SNIExtension{},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SessionTicketExtension{},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{}, // PSK must be last extension
			}),
		}, nil

	// Chrome 143 Linux with PSK for session resumption
	case HelloChrome_143_Linux_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome extension order with shuffling + PSK at end (Chrome shuffles since v110)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&StatusRequestExtension{},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				&SNIExtension{},
				&SCTExtension{},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				BoringGREASEECH(),
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SessionTicketExtension{},
				&ExtendedMasterSecretExtension{},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{}, // PSK must be last extension
			}),
		}, nil

	// Chrome 143 macOS with PSK for session resumption
	case HelloChrome_143_macOS_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome extension order with shuffling + PSK at end (Chrome shuffles since v110)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SCTExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&SNIExtension{},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				BoringGREASEECH(),
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&ExtendedMasterSecretExtension{},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{}, // PSK must be last extension
			}),
		}, nil

	// Chrome 143 QUIC with PSK for session resumption (0-RTT)
	// Real Chrome sends 13 extensions: early_data first, PSK last, rest shuffled
	case HelloChrome_143_QUIC_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Chrome QUIC extension order for resumed connections:
			// - early_data (42) at start for 0-RTT indication
			// - Shuffled middle extensions
			// - pre_shared_key (41) must be last per RFC 8446
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&FakeEarlyDataExtension{}, // early_data (42) - 0-RTT indicator
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h3"}},
				BoringGREASEECH(),
				&ALPNExtension{AlpnProtocols: []string{"h3"}},
				&SupportedCurvesExtension{[]CurveID{
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&QUICTransportParametersExtension{},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&SNIExtension{},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&UtlsPreSharedKeyExtension{}, // PSK must be last extension
			}),
		}, nil

	// Chrome 144 - TLS fingerprint identical to Chrome 143 (same ja4/peetprint hash)
	// Only HTTP headers (User-Agent, sec-ch-ua) differ between versions
	case HelloChrome_144_Windows:
		return utlsIdToSpec(HelloChrome_143_Windows)
	case HelloChrome_144_Linux:
		return utlsIdToSpec(HelloChrome_143_Linux)
	case HelloChrome_144_macOS:
		return utlsIdToSpec(HelloChrome_143_macOS)
	case HelloChrome_144_QUIC:
		return utlsIdToSpec(HelloChrome_143_QUIC)
	case HelloChrome_144_Windows_PSK:
		return utlsIdToSpec(HelloChrome_143_Windows_PSK)
	case HelloChrome_144_Linux_PSK:
		return utlsIdToSpec(HelloChrome_143_Linux_PSK)
	case HelloChrome_144_macOS_PSK:
		return utlsIdToSpec(HelloChrome_143_macOS_PSK)
	case HelloChrome_144_QUIC_PSK:
		return utlsIdToSpec(HelloChrome_143_QUIC_PSK)

	// Chrome 145 - TLS fingerprint identical to Chrome 144 (same ja4/peetprint hash)
	// Only HTTP headers (User-Agent, sec-ch-ua) differ between versions
	case HelloChrome_145_Windows:
		return utlsIdToSpec(HelloChrome_144_Windows)
	case HelloChrome_145_Linux:
		return utlsIdToSpec(HelloChrome_144_Linux)
	case HelloChrome_145_macOS:
		return utlsIdToSpec(HelloChrome_144_macOS)
	case HelloChrome_145_QUIC:
		return utlsIdToSpec(HelloChrome_144_QUIC)
	case HelloChrome_145_Windows_PSK:
		return utlsIdToSpec(HelloChrome_144_Windows_PSK)
	case HelloChrome_145_Linux_PSK:
		return utlsIdToSpec(HelloChrome_144_Linux_PSK)
	case HelloChrome_145_macOS_PSK:
		return utlsIdToSpec(HelloChrome_144_macOS_PSK)
	case HelloChrome_145_QUIC_PSK:
		return utlsIdToSpec(HelloChrome_144_QUIC_PSK)

	// Chrome 146 - TLS fingerprint identical to Chrome 145 (same ja4/peetprint hash)
	// Only HTTP headers (User-Agent, sec-ch-ua) differ between versions
	case HelloChrome_146_Windows:
		return utlsIdToSpec(HelloChrome_145_Windows)
	case HelloChrome_146_Linux:
		return utlsIdToSpec(HelloChrome_145_Linux)
	case HelloChrome_146_macOS:
		return utlsIdToSpec(HelloChrome_145_macOS)
	case HelloChrome_146_QUIC:
		return utlsIdToSpec(HelloChrome_145_QUIC)
	case HelloChrome_146_Windows_PSK:
		return utlsIdToSpec(HelloChrome_145_Windows_PSK)
	case HelloChrome_146_Linux_PSK:
		return utlsIdToSpec(HelloChrome_145_Linux_PSK)
	case HelloChrome_146_macOS_PSK:
		return utlsIdToSpec(HelloChrome_145_macOS_PSK)
	case HelloChrome_146_QUIC_PSK:
		return utlsIdToSpec(HelloChrome_145_QUIC_PSK)

	case HelloFirefox_55, HelloFirefox_56:
		return ClientHelloSpec{
			TLSVersMax: VersionTLS12,
			TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{compressionNone},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{X25519, CurveP256, CurveP384, CurveP521}},
				&SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1},
				},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
			GetSessionID: nil,
		}, nil
	case HelloFirefox_63, HelloFirefox_65:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256},
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
				&FakeRecordSizeLimitExtension{0x4001},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}}, nil
	case HelloFirefox_99:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},                  //server_name
				&ExtendedMasterSecretExtension{}, //extended_master_secret
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, //extensionRenegotiationInfo
				&SupportedCurvesExtension{[]CurveID{ //supported_groups
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{ //ec_point_formats
					pointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //application_layer_protocol_negotiation
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256}, //key_share
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13, //supported_versions
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{ //psk_key_exchange_modes
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{Limit: 0x4001},             //record_size_limit
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, //padding
			}}, nil
	case HelloFirefox_102:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&SNIExtension{},                  //server_name
				&ExtendedMasterSecretExtension{}, //extended_master_secret
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, //extensionRenegotiationInfo
				&SupportedCurvesExtension{[]CurveID{ //supported_groups
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
					CurveID(FakeFFDHE2048),
					CurveID(FakeFFDHE3072),
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{ //ec_point_formats
					pointFormatUncompressed,
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2"}}, //application_layer_protocol_negotiation
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
					{Group: CurveP256}, //key_share
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13, //supported_versions
					VersionTLS12,
				}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ //signature_algorithms
					ECDSAWithP256AndSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithP521AndSHA512,
					PSSWithSHA256,
					PSSWithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA256,
					PKCS1WithSHA384,
					PKCS1WithSHA512,
					ECDSAWithSHA1,
					PKCS1WithSHA1,
				}},
				&PSKKeyExchangeModesExtension{[]uint8{ //psk_key_exchange_modes
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{Limit: 0x4001},             //record_size_limit
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, //padding
			}}, nil
	case HelloFirefox_105:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						256,
						257,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: X25519,
						},
						{
							Group: CurveP256,
						},
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						VersionTLS13,
						VersionTLS12,
					},
				},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						PSSWithSHA256,
						PSSWithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA256,
						PKCS1WithSHA384,
						PKCS1WithSHA512,
						ECDSAWithSHA1,
						PKCS1WithSHA1,
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&FakeRecordSizeLimitExtension{
					Limit: 0x4001,
				},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloFirefox_120:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						256,
						257,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: X25519,
						},
						{
							Group: CurveP256,
						},
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						VersionTLS13,
						VersionTLS12,
					},
				},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						PSSWithSHA256,
						PSSWithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA256,
						PKCS1WithSHA384,
						PKCS1WithSHA512,
						ECDSAWithSHA1,
						PKCS1WithSHA1,
					},
				},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{
					Limit: 0x4001,
				},
				&GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []HPKESymmetricCipherSuite{
						{
							KdfId:  dicttls.HKDF_SHA256,
							AeadId: dicttls.AEAD_AES_128_GCM,
						},
						{
							KdfId:  dicttls.HKDF_SHA256,
							AeadId: dicttls.AEAD_CHACHA20_POLY1305,
						},
					},
					CandidatePayloadLens: []uint16{223}, // +16: 239
				},
			},
		}, nil
	case HelloIOS_11_1:
		return ClientHelloSpec{
			TLSVersMax: VersionTLS12,
			TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&NPNExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&SupportedCurvesExtension{Curves: []CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
			},
		}, nil
	case HelloIOS_12_1:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				compressionNone,
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&NPNExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					pointFormatUncompressed,
				}},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
			},
		}, nil
	case HelloIOS_13:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&StatusRequestExtension{},
				&SCTExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&KeyShareExtension{[]KeyShare{
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloIOS_14:
		return ClientHelloSpec{
			// TLSVersMax: VersionTLS12,
			// TLSVersMin: VersionTLS10,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				0xc008,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					CurveID(GREASE_PLACEHOLDER),
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					ECDSAWithSHA1,
					PSSWithSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
					VersionTLS11,
					VersionTLS10,
				}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloAndroid_11_OkHttp:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				0xcca9, // Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				0xcca8, // Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{},
				// supported_groups
				&SupportedCurvesExtension{[]CurveID{
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
			},
		}, nil
	case HelloEdge_85:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // pointFormatUncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
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
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloEdge_106:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
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
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&ApplicationSettingsExtension{
					SupportedProtocols: []string{
						"h2",
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloSafari_16_0:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithSHA1,
						PSSWithSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
						PKCS1WithSHA1,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionZlib,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloSafari_18:
		// Safari 18 with post-quantum X25519MLKEM768 support
		// Captured from iOS/macOS Safari 18
		// Note: Safari does NOT shuffle extensions (unlike Chrome)
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
				TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519MLKEM768,
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PSSWithSHA384, // duplicate in real Safari
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
						PKCS1WithSHA1,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data:  []byte{0},
						},
						{
							Group: X25519MLKEM768,
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionZlib,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloIOS_18:
		// iOS 18 Safari - same TLS as Safari 18 (WebKit requirement)
		// All iOS browsers use Safari's TLS stack
		return UTLSIdToSpec(HelloSafari_18)

	case HelloIOS_18_QUIC:
		// iOS 18 Safari QUIC fingerprint - captured from real iOS Chrome 144
		// iOS Chrome uses WebKit/Safari for H3 (Apple requirement)
		// Key differences from Chrome QUIC:
		// - Has GREASE extensions (multiple)
		// - Has status_request (5) and SCT (18)
		// - Uses zlib for compress_certificate (not brotli)
		// - Different cipher order (GREASE, AES256, CHACHA, AES128)
		// - NO application_settings (17613)
		// - NO ECH (65037)
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_128_GCM_SHA256,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			// Safari/iOS QUIC extension order - from real iOS Chrome 144 capture
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				// server_name (0)
				&SNIExtension{},
				// supported_groups (10) - with GREASE
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				// application_layer_protocol_negotiation (16)
				&ALPNExtension{AlpnProtocols: []string{"h3"}},
				// status_request (5) - Safari includes OCSP stapling
				&StatusRequestExtension{},
				// signature_algorithms (13) - real iOS has rsa_pss_rsae_sha384 duplicated
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PSSWithSHA384, // Duplicate - real iOS Chrome sends this twice
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
					PKCS1WithSHA1,
				}},
				// signed_certificate_timestamp (18)
				&SCTExtension{},
				// key_share (51) - with GREASE
				&KeyShareExtension{[]KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				// psk_key_exchange_modes (45)
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				// supported_versions (43) - with GREASE
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
				}},
				// quic_transport_parameters (57)
				&QUICTransportParametersExtension{},
				// compress_certificate (27) - Safari uses zlib, not brotli
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionZlib,
				}},
				&UtlsGREASEExtension{},
			},
		}, nil

	case Hello360_7_5:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
				TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
				FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
				FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_RC4_128_SHA,
				FAKE_TLS_RSA_WITH_RC4_128_MD5,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA256,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						CurveP256,
						CurveP384,
						CurveP521,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // pointFormatUncompressed
					},
				},
				&SessionTicketExtension{},
				&NPNExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"spdy/2",
						"spdy/3",
						"spdy/3.1",
						"http/1.1",
					},
				},
				&FakeChannelIDExtension{
					OldExtensionID: true,
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						PKCS1WithSHA256,
						PKCS1WithSHA384,
						PKCS1WithSHA1,
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithSHA1,
						FakeSHA256WithDSA,
						FakeSHA1WithDSA,
					},
				},
			},
		}, nil
	case Hello360_11_0:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
						PKCS1WithSHA1,
					},
				},
				&SCTExtension{},
				&FakeChannelIDExtension{
					OldExtensionID: false,
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloQQ_11_1:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS10,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
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
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
						VersionTLS11,
						VersionTLS10,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&ApplicationSettingsExtension{
					SupportedProtocols: []string{
						"h2",
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloChrome_100_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			},
		}, nil
	case HelloChrome_112_PSK_Shuf:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	case HelloChrome_114_Padding_PSK_Shuf:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement
	case HelloChrome_115_PQ_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	default:
		if id.Client == helloRandomized || id.Client == helloRandomizedALPN || id.Client == helloRandomizedNoALPN {
			// Use empty values as they can be filled later by UConn.ApplyPreset or manually.
			return generateRandomizedSpec(&id, "", nil)
		}

		return ClientHelloSpec{}, fmt.Errorf("%w: %s", ErrUnknownClientHelloID, id.Str())
	}
}

// ShuffleChromeTLSExtensions shuffles the extensions in the ClientHelloSpec to avoid ossification.
// It shuffles every extension except GREASE, padding and pre_shared_key extensions.
//
// This feature was first introduced by Chrome 106.
// positionInvariantExtension reports whether an extension is pinned to its
// slot and must never be permuted. GREASE extensions bracket the list, padding
// has to stay last so it can size the record, and pre_shared_key is required by
// RFC 8446 4.2.11 to be the final extension.
func positionInvariantExtension(ext TLSExtension) bool {
	switch ext.(type) {
	case *UtlsGREASEExtension, *UtlsPaddingExtension, PreSharedKeyExtension:
		return true
	default:
		return false
	}
}

// shufflePermutable permutes the extensions that may move, leaving every
// position-invariant extension in the slot it already occupies.
//
// It permutes a compacted list of the movable extensions and writes the result
// back into the slots they came from, rather than shuffling the whole list and
// declining the swaps that touch an invariant slot.
//
// Declining the swap is the intuitive version and it does not produce a uniform
// permutation. Fisher-Yates draws a partner for each position; when the partner
// lands on an invariant slot the element simply stays where it is, and it stays
// there more often than chance. Measured over 20000 shuffles of a Chrome-shaped
// list of 15 movable and 3 invariant extensions, every movable extension sat at
// its canonical index about 12.5 percent of the time against a uniform
// expectation of 6.67. Close to twice as likely as chance, for every extension
// at once, which is a population-level signature of the shuffler rather than of
// the browser it is imitating.
func shufflePermutable(exts []TLSExtension, swap func(n int, fn func(i, j int))) {
	idx := make([]int, 0, len(exts))
	for i := range exts {
		if !positionInvariantExtension(exts[i]) {
			idx = append(idx, i)
		}
	}
	if len(idx) < 2 {
		return
	}
	movable := make([]TLSExtension, len(idx))
	for k, i := range idx {
		movable[k] = exts[i]
	}
	swap(len(movable), func(i, j int) {
		movable[i], movable[j] = movable[j], movable[i]
	})
	for k, i := range idx {
		exts[i] = movable[k]
	}
}

func ShuffleChromeTLSExtensions(exts []TLSExtension) []TLSExtension {
	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		// warning: random could be deterministic
		shufflePermutable(exts, rand.Shuffle)
		fmt.Println("Warning: failed to use a cryptographically secure random number generator. The shuffle can be deterministic.")
		return exts
	}
	shufflePermutable(exts, rand.New(rand.NewSource(randInt64.Int64())).Shuffle)
	return exts
}

func ShuffleChromeTLSExtensionsWithSeed(exts []TLSExtension, seed int64) []TLSExtension {
	shufflePermutable(exts, rand.New(rand.NewSource(seed)).Shuffle)
	return exts
}

func (uconn *UConn) applyPresetByID(id ClientHelloID) (err error) {

	if uconn.clientHelloSpec == nil {
		var spec ClientHelloSpec
		uconn.ClientHelloID = id

		// choose/generate the spec
		switch id.Client {
		case helloRandomized, helloRandomizedNoALPN, helloRandomizedALPN:
			spec, err = uconn.generateRandomizedSpec()
			if err != nil {
				return err
			}
		case helloCustom:
			return nil
		default:
			spec, err = UTLSIdToSpec(id)
			if err != nil {
				return err
			}
		}

		uconn.clientHelloSpec = &spec
	}

	return uconn.ApplyPreset(uconn.clientHelloSpec)
}

// ApplyPreset should only be used in conjunction with HelloCustom to apply custom specs.
// Fields of TLSExtensions that are slices/pointers are shared across different connections with
// same ClientHelloSpec. It is advised to use different specs and avoid any shared state.
func (uconn *UConn) ApplyPreset(p *ClientHelloSpec) error {
	var err error

	err = uconn.SetTLSVers(p.TLSVersMin, p.TLSVersMax, p.Extensions)
	if err != nil {
		return err
	}

	privateHello, clientKeySharePrivate, ech, err := uconn.makeClientHelloForApplyPreset()
	if err != nil {
		return err
	}
	uconn.HandshakeState.Hello = privateHello.getPublicPtr()
	if clientKeySharePrivate != nil {
		uconn.HandshakeState.State13.KeyShareKeys = clientKeySharePrivate.ToPublic()
	} else {
		uconn.HandshakeState.State13.KeyShareKeys = &KeySharePrivateKeys{}
	}
	uconn.echCtx = ech
	hello := uconn.HandshakeState.Hello

	switch len(hello.Random) {
	case 0:
		hello.Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.config.rand(), hello.Random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	case 32:
	// carry on
	default:
		return errors.New("ClientHello expected length: 32 bytes. Got: " +
			strconv.Itoa(len(hello.Random)) + " bytes")
	}

	if len(hello.CompressionMethods) == 0 {
		hello.CompressionMethods = []uint8{compressionNone}
	}

	// Currently, GREASE is assumed to come from BoringSSL
	grease_extensions_seen := 0

	// Check if spec has cached GREASESeed (non-zero means it was set)
	hasGREASESeed := false
	for _, v := range p.GREASESeed {
		if v != 0 {
			hasGREASESeed = true
			break
		}
	}

	if hasGREASESeed {
		// Use the cached GREASE seed from the spec
		uconn.greaseSeed = p.GREASESeed
	} else {
		// Generate new random GREASE values
		grease_bytes := make([]byte, 2*ssl_grease_seed_len)
		_, err = io.ReadFull(uconn.config.rand(), grease_bytes)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
		for i := range uconn.greaseSeed {
			uconn.greaseSeed[i] = binary.LittleEndian.Uint16(grease_bytes[2*i : 2*i+2])
		}
		if GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1) == GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2) {
			uconn.greaseSeed[ssl_grease_extension2] ^= 0x1010
		}
	}

	hello.CipherSuites = make([]uint16, len(p.CipherSuites))
	copy(hello.CipherSuites, p.CipherSuites)
	for i := range hello.CipherSuites {
		if isGREASEUint16(hello.CipherSuites[i]) { // just in case the user set a GREASE value instead of unGREASEd
			hello.CipherSuites[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_cipher)
		}
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if uconn.quic == nil {
		var sessionID [32]byte
		_, err = io.ReadFull(uconn.config.rand(), sessionID[:])
		if err != nil {
			return err
		}
		uconn.HandshakeState.Hello.SessionId = sessionID[:]
	}

	uconn.Extensions = make([]TLSExtension, len(p.Extensions))
	copy(uconn.Extensions, p.Extensions)

	// Check whether NPN extension actually exists
	var haveNPN bool

	// reGrease, and point things to each other
	for i, e := range uconn.Extensions {
		switch ext := e.(type) {
		case *SNIExtension:
			if ext.ServerName == "" {
				ext.ServerName = uconn.config.ServerName
			}
			if uconn.config.EncryptedClientHelloConfigList != nil {
				ext.ServerName = string(ech.config.PublicName)
			}
		case *UtlsGREASEExtension:
			switch grease_extensions_seen {
			case 0:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1)
			case 1:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2)
				ext.Body = []byte{0}
			default:
				return errors.New("at most 2 grease extensions are supported")
			}
			grease_extensions_seen += 1
		case *SupportedCurvesExtension:
			for i := range ext.Curves {
				if isGREASEUint16(uint16(ext.Curves[i])) {
					ext.Curves[i] = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
				}
			}
		case *SignatureAlgorithmsExtension:
			regreaseSignatureAlgorithms(ext, uconn.greaseSeed)
		case *KeyShareExtension:
			preferredCurveIsSet := false
			for i := range ext.KeyShares {
				curveID := ext.KeyShares[i].Group
				if isGREASEUint16(uint16(curveID)) { // just in case the user set a GREASE value instead of unGREASEd
					ext.KeyShares[i].Group = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
					// GREASE keyshares need random 1-byte data
					if len(ext.KeyShares[i].Data) == 0 {
						ext.KeyShares[i].Data = []byte{0x00}
					}
					continue
				}
				// Always regenerate keys for non-GREASE curves (clear existing data)
				// This ensures fresh keys for each connection when spec is reused
				ext.KeyShares[i].Data = nil

				if curveID == X25519MLKEM768 || curveID == X25519Kyber768Draft00 {
					ecdheKey, err := generateECDHEKey(uconn.config.rand(), X25519)
					if err != nil {
						return err
					}
					seed := make([]byte, mlkem.SeedSize)
					if _, err := io.ReadFull(uconn.config.rand(), seed); err != nil {
						return err
					}
					mlkemKey, err := mlkem.NewDecapsulationKey768(seed)
					if err != nil {
						return err
					}

					if curveID == X25519Kyber768Draft00 {
						ext.KeyShares[i].Data = append(ecdheKey.PublicKey().Bytes(), mlkemKey.EncapsulationKey().Bytes()...)
					} else {
						ext.KeyShares[i].Data = append(mlkemKey.EncapsulationKey().Bytes(), ecdheKey.PublicKey().Bytes()...)
					}
					uconn.HandshakeState.State13.KeyShareKeys.Mlkem = mlkemKey
					uconn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe = ecdheKey
				} else {
					ecdheKey, err := generateECDHEKey(uconn.config.rand(), curveID)
					if err != nil {
						return fmt.Errorf("unsupported Curve in KeyShareExtension: %v."+
							"To mimic it, fill the Data(key) field manually", curveID)
					}

					ext.KeyShares[i].Data = ecdheKey.PublicKey().Bytes()
					if !preferredCurveIsSet {
						// only do this once for the first non-grease curve
						uconn.HandshakeState.State13.KeyShareKeys.Ecdhe = ecdheKey
						preferredCurveIsSet = true
					}
				}
			}
		case *SupportedVersionsExtension:
			for i := range ext.Versions {
				if isGREASEUint16(ext.Versions[i]) { // just in case the user set a GREASE value instead of unGREASEd
					ext.Versions[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_version)
				}
			}
		case *NPNExtension:
			haveNPN = true
		case *QUICTransportParametersExtension:
			// For QUIC connections, fill in the transport parameters from the QUIC layer
			// We need to create a new instance to avoid sharing state across connections
			if uconn.quic != nil && uconn.quic.transportParams != nil {
				newExt := &QUICTransportParametersExtension{
					RawData: uconn.quic.transportParams,
				}
				uconn.Extensions[i] = newExt
			}
		}
	}

	// The default golang behavior in makeClientHello always sets NextProtoNeg if NextProtos is set,
	// but NextProtos is also used by ALPN and our spec nmay not actually have a NPN extension
	hello.NextProtoNeg = haveNPN

	err = uconn.sessionController.syncSessionExts()
	if err != nil {
		return err
	}

	return nil
}

func (uconn *UConn) generateRandomizedSpec() (ClientHelloSpec, error) {
	return generateRandomizedSpec(&uconn.ClientHelloID, uconn.serverName, uconn.config.NextProtos)
}

func generateRandomizedSpec(
	id *ClientHelloID,
	serverName string,
	nextProtos []string,
) (ClientHelloSpec, error) {
	p := ClientHelloSpec{}

	if id.Seed == nil {
		seed, err := NewPRNGSeed()
		if err != nil {
			return p, err
		}
		id.Seed = seed
	}

	r, err := newPRNGWithSeed(id.Seed)
	if err != nil {
		return p, err
	}

	if id.Weights == nil {
		id.Weights = &DefaultWeights
	}

	var WithALPN bool
	switch id.Client {
	case helloRandomizedALPN:
		WithALPN = true
	case helloRandomizedNoALPN:
		WithALPN = false
	case helloRandomized:
		if r.FlipWeightedCoin(id.Weights.Extensions_Append_ALPN) {
			WithALPN = true
		} else {
			WithALPN = false
		}
	default:
		return p, fmt.Errorf("using non-randomized ClientHelloID %v to generate randomized spec", id.Client)
	}

	p.CipherSuites = defaultCipherSuites()
	shuffledSuites, err := shuffledCiphers(r)
	if err != nil {
		return p, err
	}

	if r.FlipWeightedCoin(id.Weights.TLSVersMax_Set_VersionTLS13) {
		// randomize min TLS version
		minTLSVersCandidates := []uint16{VersionTLS10, VersionTLS12}
		p.TLSVersMin = minTLSVersCandidates[r.Intn(len(minTLSVersCandidates))]
		p.TLSVersMax = VersionTLS13
		tls13ciphers := make([]uint16, len(defaultCipherSuitesTLS13))
		copy(tls13ciphers, defaultCipherSuitesTLS13)
		r.rand.Shuffle(len(tls13ciphers), func(i, j int) {
			tls13ciphers[i], tls13ciphers[j] = tls13ciphers[j], tls13ciphers[i]
		})
		// appending TLS 1.3 ciphers before TLS 1.2, since that's what popular implementations do
		shuffledSuites = append(tls13ciphers, shuffledSuites...)

		// TLS 1.3 forbids RC4 in any configurations
		shuffledSuites = removeRC4Ciphers(shuffledSuites)
	} else {
		p.TLSVersMin = VersionTLS10
		p.TLSVersMax = VersionTLS12
	}

	p.CipherSuites = removeRandomCiphers(r, shuffledSuites, id.Weights.CipherSuites_Remove_RandomCiphers)

	sni := SNIExtension{serverName}
	sessionTicket := SessionTicketExtension{}

	sigAndHashAlgos := []SignatureScheme{
		ECDSAWithP256AndSHA256,
		PKCS1WithSHA256,
		ECDSAWithP384AndSHA384,
		PKCS1WithSHA384,
		PKCS1WithSHA1,
		PKCS1WithSHA512,
	}

	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_ECDSAWithSHA1) {
		sigAndHashAlgos = append(sigAndHashAlgos, ECDSAWithSHA1)
	}
	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_ECDSAWithP521AndSHA512) {
		sigAndHashAlgos = append(sigAndHashAlgos, ECDSAWithP521AndSHA512)
	}
	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_PSSWithSHA256) || p.TLSVersMax == VersionTLS13 {
		// https://tools.ietf.org/html/rfc8446 says "...RSASSA-PSS (which is mandatory in TLS 1.3)..."
		sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA256)
		if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512) {
			// these usually go together
			sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA384)
			sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA512)
		}
	}

	r.rand.Shuffle(len(sigAndHashAlgos), func(i, j int) {
		sigAndHashAlgos[i], sigAndHashAlgos[j] = sigAndHashAlgos[j], sigAndHashAlgos[i]
	})
	sigAndHash := SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAndHashAlgos}

	status := StatusRequestExtension{}
	sct := SCTExtension{}
	ems := ExtendedMasterSecretExtension{}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}

	curveIDs := []CurveID{}
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_X25519) && p.TLSVersMax == VersionTLS13 {
		curveIDs = append(curveIDs, X25519MLKEM768)
	}
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_X25519) || p.TLSVersMax == VersionTLS13 {
		curveIDs = append(curveIDs, X25519)
	}
	curveIDs = append(curveIDs, CurveP256, CurveP384)
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_CurveP521) {
		curveIDs = append(curveIDs, CurveP521)
	}

	curves := SupportedCurvesExtension{curveIDs}

	padding := UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}
	reneg := RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}

	p.Extensions = []TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&points,
		&curves,
	}

	if WithALPN {
		if len(nextProtos) == 0 {
			// if user didn't specify alpn yet, choose something popular
			nextProtos = []string{"h2", "http/1.1"}
		}
		alpn := ALPNExtension{AlpnProtocols: nextProtos}
		p.Extensions = append(p.Extensions, &alpn)
	}

	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Padding) || p.TLSVersMax == VersionTLS13 {
		// always include for TLS 1.3, since TLS 1.3 ClientHellos are often over 256 bytes
		// and that's when padding is required to work around buggy middleboxes
		p.Extensions = append(p.Extensions, &padding)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Status) {
		p.Extensions = append(p.Extensions, &status)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_SCT) {
		p.Extensions = append(p.Extensions, &sct)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Reneg) {
		p.Extensions = append(p.Extensions, &reneg)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_EMS) {
		p.Extensions = append(p.Extensions, &ems)
	}
	if p.TLSVersMax == VersionTLS13 {
		ks := KeyShareExtension{[]KeyShare{
			{Group: X25519}, // the key for the group will be generated later
		}}
		if r.FlipWeightedCoin(id.Weights.FirstKeyShare_Set_CurveP256) { // legacy setting, not used by default
			ks.KeyShares[0].Group = CurveP256
		} else {
			if r.FlipWeightedCoin(id.Weights.KeyShare_Append_RandomGroups) {
				ks.KeyShares = append(ks.KeyShares, KeyShare{Group: CurveP256})
			}
			if r.FlipWeightedCoin(id.Weights.KeyShare_Append_RandomGroups) {
				ks.KeyShares = append([]KeyShare{{Group: X25519MLKEM768}}, ks.KeyShares...)
			}
		}
		pskExchangeModes := PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}}
		supportedVersionsExt := SupportedVersionsExtension{
			Versions: makeSupportedVersions(p.TLSVersMin, p.TLSVersMax),
		}
		p.Extensions = append(p.Extensions, &ks, &pskExchangeModes, &supportedVersionsExt)

		// Randomly add an ALPS extension. ALPS is TLS 1.3-only and may only
		// appear when an ALPN extension is present
		// (https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01#section-3).
		// ALPS is a draft specification at this time, but appears in
		// Chrome/BoringSSL.
		if WithALPN {

			// ALPS is a new addition to generateRandomizedSpec. Use a salted
			// seed to create a new, independent PRNG, so that a seed used
			// with the previous version of generateRandomizedSpec will
			// produce the exact same spec as long as ALPS isn't selected.
			r, err := newPRNGWithSaltedSeed(id.Seed, "ALPS")
			if err != nil {
				return p, err
			}
			if r.FlipWeightedCoin(id.Weights.Extensions_Append_ALPS) {
				// As with the ALPN case above, default to something popular
				// (unlike ALPN, ALPS can't yet be specified in uconn.config).
				alps := &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
				p.Extensions = append(p.Extensions, alps)
			}
		}

		// TODO: randomly add DelegatedCredentialsExtension, once it is
		// sufficiently popular.
	}
	r.rand.Shuffle(len(p.Extensions), func(i, j int) {
		p.Extensions[i], p.Extensions[j] = p.Extensions[j], p.Extensions[i]
	})

	return p, nil
}

func removeRandomCiphers(r *prng, s []uint16, maxRemovalProbability float64) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float64(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if r.FlipWeightedCoin(maxRemovalProbability * float64(i) / floatLen) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

func shuffledCiphers(r *prng) ([]uint16, error) {
	ciphers := make(sortableCiphers, len(cipherSuites))
	perm := r.Perm(len(cipherSuites))
	for i, suite := range cipherSuites {
		ciphers[i] = sortableCipher{suite: suite.id,
			isObsolete: ((suite.flags & suiteTLS12) == 0),
			randomTag:  perm[i]}
	}
	sort.Sort(ciphers)
	return ciphers.GetCiphers(), nil
}

type sortableCipher struct {
	isObsolete bool
	randomTag  int
	suite      uint16
}

type sortableCiphers []sortableCipher

func (ciphers sortableCiphers) Len() int {
	return len(ciphers)
}

func (ciphers sortableCiphers) Less(i, j int) bool {
	if ciphers[i].isObsolete && !ciphers[j].isObsolete {
		return false
	}
	if ciphers[j].isObsolete && !ciphers[i].isObsolete {
		return true
	}
	return ciphers[i].randomTag < ciphers[j].randomTag
}

func (ciphers sortableCiphers) Swap(i, j int) {
	ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
}

func (ciphers sortableCiphers) GetCiphers() []uint16 {
	cipherIDs := make([]uint16, len(ciphers))
	for i := range ciphers {
		cipherIDs[i] = ciphers[i].suite
	}
	return cipherIDs
}

func removeRC4Ciphers(s []uint16) []uint16 {
	// removes elements in place
	sliceLen := len(s)
	for i := 0; i < sliceLen; i++ {
		cipher := s[i]
		if cipher == TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ||
			cipher == TLS_ECDHE_RSA_WITH_RC4_128_SHA ||
			cipher == TLS_RSA_WITH_RC4_128_SHA {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

// cookieSpliceRange gives the inclusive range of insertion indices for the
// cookie extension echoed in the second ClientHello after a HelloRetryRequest.
//
// The cookie belongs in the permutable middle: never ahead of the leading
// GREASE extension, and never behind the trailing run of pinned extensions,
// which is padding, the trailing GREASE and pre_shared_key in whatever
// combination the spec carries. Computing both runs rather than subtracting a
// constant is what makes this correct for a spec that carries pre_shared_key
// and one that does not, which differ in length.
//
// Inserting at hi places the cookie immediately before that trailing run.
func cookieSpliceRange(exts []TLSExtension) (lo, hi int) {
	first, last := -1, -1
	for i := range exts {
		if !positionInvariantExtension(exts[i]) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first < 0 {
		// No permutable extension at all, which no real spec produces. Put the
		// cookie after the leading extension rather than ahead of it, so the
		// GREASE a browser always leads with still leads.
		if len(exts) == 0 {
			return 0, 0
		}
		return 1, 1
	}
	return first, last + 1
}

// regreaseSignatureAlgorithms replaces every GREASE placeholder in a
// signature_algorithms extension with this connection's own value.
//
// Chrome greases signature_algorithms from version 152.
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
// so the fake one is written BEFORE the real list, and where it sits is the
// preset's business. Substituting in place matches how ciphers and curves are
// handled, so the preset decides the position.
//
// A captured hello re-parsed through Write lands here too: the captured value
// is itself a GREASE value, so it is replaced by this connection's own rather
// than replayed.
func regreaseSignatureAlgorithms(ext *SignatureAlgorithmsExtension, seed [ssl_grease_seed_len]uint16) {
	for i := range ext.SupportedSignatureAlgorithms {
		if isGREASEUint16(uint16(ext.SupportedSignatureAlgorithms[i])) {
			ext.SupportedSignatureAlgorithms[i] = SignatureScheme(
				GetBoringGREASEValue(seed, ssl_grease_signature_algorithm))
		}
	}
}

// RegreaseSignatureAlgorithms re-runs that substitution over the extensions a
// connection is holding, using its own seed.
//
// It exists for callers that build a hello from a ClientHelloID and then edit
// uconn.Extensions afterwards, which happens after ApplyPreset has already
// regreased and so misses any placeholder introduced by the edit. Without it
// such a caller emits the literal 0x0a0a placeholder on every connection: a
// constant where the browser draws one of sixteen.
func (uconn *UConn) RegreaseSignatureAlgorithms() {
	for _, ext := range uconn.Extensions {
		if sa, ok := ext.(*SignatureAlgorithmsExtension); ok {
			regreaseSignatureAlgorithms(sa, uconn.greaseSeed)
		}
	}
}
