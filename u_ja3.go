package tls

import (
	"fmt"
	"strconv"
	"strings"
)

// JA3Extras contains optional overrides for JA3-parsed ClientHelloSpec.
// Fields left nil/empty will use sensible defaults.
type JA3Extras struct {
	// SignatureAlgorithms overrides the signature_algorithms extension (13).
	// Names match IANA registry: "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", etc.
	SignatureAlgorithms []string

	// ALPN overrides the ALPN extension (16). Default: ["h2", "http/1.1"]
	ALPN []string

	// CertCompression overrides compress_certificate algorithms.
	// Default: [brotli] when extension 27 is present in JA3.
	CertCompression []CertCompressionAlgo

	// PermuteExtensions enables random extension permutation (Chrome-style).
	PermuteExtensions bool
}

// sigAlgNameToScheme maps human-readable sig alg names to TLS SignatureScheme values.
var sigAlgNameToScheme = map[string]SignatureScheme{
	"rsa_pkcs1_sha1":          0x0201,
	"ecdsa_sha1":              0x0203,
	"rsa_pkcs1_sha256":        0x0401,
	"ecdsa_secp256r1_sha256":  0x0403,
	"rsa_pkcs1_sha384":        0x0501,
	"ecdsa_secp384r1_sha384":  0x0503,
	"rsa_pkcs1_sha512":        0x0601,
	"ecdsa_secp521r1_sha512":  0x0603,
	"rsa_pss_rsae_sha256":     0x0804,
	"rsa_pss_rsae_sha384":     0x0805,
	"rsa_pss_rsae_sha512":     0x0806,
	"ed25519":                 0x0807,
	"ed448":                   0x0808,
	"rsa_pss_pss_sha256":      0x0809,
	"rsa_pss_pss_sha384":      0x080A,
	"rsa_pss_pss_sha512":      0x080B,
}

// defaultSigAlgs is the default signature algorithm list (matches Chrome).
var defaultSigAlgs = []SignatureScheme{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
}

// FromJA3 parses a JA3 fingerprint string into a ClientHelloSpec.
//
// JA3 format: TLSVersion,CipherSuites,Extensions,Curves,PointFormats
// Example: "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0"
//
// The extras parameter allows overriding defaults for signature algorithms, ALPN, etc.
// Pass nil for all defaults.
func FromJA3(ja3 string, extras *JA3Extras) (*ClientHelloSpec, error) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JA3 format: expected 5 comma-separated fields, got %d", len(parts))
	}

	// Parse TLS version
	tlsVersion, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS version: %w", err)
	}

	// Parse cipher suites
	cipherSuites, err := parseUint16List(parts[1], "-")
	if err != nil {
		return nil, fmt.Errorf("invalid cipher suites: %w", err)
	}

	// Parse extension IDs
	extensionIDs, err := parseUint16List(parts[2], "-")
	if err != nil {
		return nil, fmt.Errorf("invalid extensions: %w", err)
	}

	// Parse curves (supported groups)
	curves, err := parseUint16List(parts[3], "-")
	if err != nil {
		return nil, fmt.Errorf("invalid curves: %w", err)
	}

	// Parse point formats
	pointFormats, err := parseUint8List(parts[4], "-")
	if err != nil {
		return nil, fmt.Errorf("invalid point formats: %w", err)
	}

	// Determine signature algorithms
	sigAlgs := defaultSigAlgs
	if extras != nil && len(extras.SignatureAlgorithms) > 0 {
		sigAlgs = make([]SignatureScheme, 0, len(extras.SignatureAlgorithms))
		for _, name := range extras.SignatureAlgorithms {
			scheme, ok := sigAlgNameToScheme[name]
			if !ok {
				// Try parsing as numeric value
				v, err := strconv.ParseUint(name, 0, 16)
				if err != nil {
					return nil, fmt.Errorf("unknown signature algorithm: %q", name)
				}
				scheme = SignatureScheme(v)
			}
			sigAlgs = append(sigAlgs, scheme)
		}
	}

	// Determine ALPN
	alpn := []string{"h2", "http/1.1"}
	if extras != nil && len(extras.ALPN) > 0 {
		alpn = extras.ALPN
	}

	// Determine cert compression algorithms
	certCompAlgs := []CertCompressionAlgo{CertCompressionBrotli}
	if extras != nil && len(extras.CertCompression) > 0 {
		certCompAlgs = extras.CertCompression
	}

	// Build extensions
	extensions, err := buildExtensionsFromIDs(extensionIDs, curves, pointFormats, sigAlgs, alpn, certCompAlgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Determine TLS version range
	var versMin, versMax uint16
	versMax = uint16(tlsVersion)
	if versMax >= VersionTLS13 {
		versMin = VersionTLS12
	} else {
		versMin = VersionTLS10
	}

	// Check if SupportedVersions extension is in the list - if so, set versions to 0
	// to let the extension control version negotiation
	for _, extID := range extensionIDs {
		if extID == 43 { // extensionSupportedVersions
			versMin = 0
			versMax = 0
			break
		}
	}

	spec := &ClientHelloSpec{
		CipherSuites:       cipherSuites,
		CompressionMethods: []uint8{0}, // null compression
		Extensions:         extensions,
		TLSVersMin:         versMin,
		TLSVersMax:         versMax,
	}

	return spec, nil
}

// buildExtensionsFromIDs maps extension IDs to concrete TLSExtension structs,
// populating them with the JA3-parsed data and extras.
func buildExtensionsFromIDs(
	extensionIDs []uint16,
	curves []uint16,
	pointFormats []uint8,
	sigAlgs []SignatureScheme,
	alpn []string,
	certCompAlgs []CertCompressionAlgo,
) ([]TLSExtension, error) {
	extensions := make([]TLSExtension, 0, len(extensionIDs))

	// Convert curves to CurveID
	curveIDs := make([]CurveID, len(curves))
	for i, c := range curves {
		curveIDs[i] = CurveID(c)
	}

	// Build KeyShare entries from curves (excluding GREASE and post-quantum for size reasons)
	keyShareCurves := make([]KeyShare, 0, len(curves))
	for _, c := range curves {
		if isGREASEUint16(c) {
			keyShareCurves = append(keyShareCurves, KeyShare{Group: CurveID(c), Data: []byte{0}})
			continue
		}
		// Only include curves that have reasonable key share sizes
		switch CurveID(c) {
		case CurveX25519:
			keyShareCurves = append(keyShareCurves, KeyShare{Group: CurveID(c), Data: make([]byte, 32)})
		case CurveSECP256R1:
			keyShareCurves = append(keyShareCurves, KeyShare{Group: CurveID(c), Data: make([]byte, 65)})
		case CurveSECP384R1:
			keyShareCurves = append(keyShareCurves, KeyShare{Group: CurveID(c), Data: make([]byte, 97)})
		case X25519Kyber768Draft00:
			keyShareCurves = append(keyShareCurves, KeyShare{Group: CurveID(c), Data: make([]byte, 1216)})
		}
	}

	// Determine supported versions for SupportedVersions extension
	supportedVersions := []uint16{VersionTLS13, VersionTLS12}

	for _, extID := range extensionIDs {
		var ext TLSExtension

		switch extID {
		case 0: // server_name (SNI) - hostname set by UConn at handshake time
			ext = &SNIExtension{}

		case 5: // status_request (OCSP stapling)
			ext = &StatusRequestExtension{}

		case 10: // supported_groups (curves)
			ext = &SupportedCurvesExtension{Curves: curveIDs}

		case 11: // ec_point_formats
			ext = &SupportedPointsExtension{SupportedPoints: pointFormats}

		case 13: // signature_algorithms
			ext = &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAlgs}

		case 16: // ALPN
			ext = &ALPNExtension{AlpnProtocols: alpn}

		case 17: // status_request_v2
			ext = &StatusRequestV2Extension{}

		case 18: // signed_certificate_timestamp (SCT)
			ext = &SCTExtension{}

		case 21: // padding
			ext = &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}

		case 22: // encrypt_then_mac
			ext = &FakeTokenBindingExtension{} // fakeExtensionEncryptThenMAC uses same ID as token binding? No.
			// Actually 22 is encrypt_then_mac, 24 is token_binding
			ext = &GenericExtension{Id: 22, Data: []byte{}}

		case 23: // extended_master_secret
			ext = &ExtendedMasterSecretExtension{}

		case 24: // token_binding
			ext = &FakeTokenBindingExtension{}

		case 27: // compress_certificate
			ext = &UtlsCompressCertExtension{Algorithms: certCompAlgs}

		case 28: // record_size_limit
			ext = &FakeRecordSizeLimitExtension{Limit: 0x4001}

		case 34: // delegated_credentials
			ext = &FakeDelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []SignatureScheme{
					0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
					0x0401, 0x0501, 0x0601,
				},
			}

		case 35: // session_ticket
			ext = &SessionTicketExtension{}

		case 43: // supported_versions
			ext = &SupportedVersionsExtension{Versions: supportedVersions}

		case 45: // psk_key_exchange_modes
			ext = &PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}}

		case 50: // signature_algorithms_cert
			ext = &SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: sigAlgs}

		case 51: // key_share
			ext = &KeyShareExtension{KeyShares: keyShareCurves}

		case 57: // quic_transport_parameters
			ext = &QUICTransportParametersExtension{}

		case 13172: // next_protocol_negotiation (NPN)
			ext = &NPNExtension{}

		case 17513: // application_settings (ALPS old)
			ext = &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}

		case 17613: // application_settings (ALPS new)
			ext = &ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}

		case 30031: // channel_id (old)
			ext = &FakeChannelIDExtension{OldExtensionID: true}

		case 30032: // channel_id
			ext = &FakeChannelIDExtension{}

		case 0xfe0d: // encrypted_client_hello (ECH)
			ext = &GREASEEncryptedClientHelloExtension{}

		case 0xff01: // renegotiation_info
			ext = &RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}

		default:
			if isGREASEUint16(extID) {
				ext = &UtlsGREASEExtension{}
			} else {
				// Unknown extension - add as generic empty extension
				ext = &GenericExtension{Id: extID, Data: []byte{}}
			}
		}

		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// parseUint16List parses a separated string of uint16 values.
func parseUint16List(s, sep string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, sep)
	result := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid uint16 value %q: %w", p, err)
		}
		result = append(result, uint16(v))
	}
	return result, nil
}

// parseUint8List parses a separated string of uint8 values.
func parseUint8List(s, sep string) ([]uint8, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, sep)
	result := make([]uint8, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid uint8 value %q: %w", p, err)
		}
		result = append(result, uint8(v))
	}
	return result, nil
}
