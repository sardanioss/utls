package tls

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// The extension shuffle has to produce a uniform permutation of the movable
// extensions while leaving the pinned ones exactly where they are.
//
// The intuitive implementation does neither. Shuffling the whole list and
// declining the swaps that touch a pinned slot leaves every movable extension
// at its canonical index far more often than chance, because Fisher-Yates
// draws a partner for each position and a partner landing on a pinned slot
// means the element simply stays put. Measured on the list below: about 12.5
// percent against a uniform expectation of 6.67, for every extension at once.
// That is a signature of the shuffler, not of the browser being imitated, and
// a population of clients sharing it is visible in aggregate.

// shuffleFixture is Chrome-shaped: GREASE at both ends, padding last, a
// realistic run of movable extensions in between.
func shuffleFixture() []TLSExtension {
	return []TLSExtension{
		&UtlsGREASEExtension{},
		&SNIExtension{},
		&ExtendedMasterSecretExtension{},
		&RenegotiationInfoExtension{},
		&SupportedCurvesExtension{},
		&SupportedPointsExtension{},
		&SessionTicketExtension{},
		&ALPNExtension{},
		&StatusRequestExtension{},
		&SignatureAlgorithmsExtension{},
		&SCTExtension{},
		&KeyShareExtension{},
		&PSKKeyExchangeModesExtension{},
		&SupportedVersionsExtension{},
		&UtlsCompressCertExtension{},
		&ApplicationSettingsExtension{},
		&UtlsGREASEExtension{},
		&UtlsPaddingExtension{},
	}
}

func movableIndices(exts []TLSExtension) []int {
	var out []int
	for i := range exts {
		if !positionInvariantExtension(exts[i]) {
			out = append(out, i)
		}
	}
	return out
}

// A pinned extension never moves. GREASE brackets the list, padding sizes the
// record, and pre_shared_key is required by RFC 8446 4.2.11 to be last.
func TestShuffleLeavesPinnedExtensionsInPlace(t *testing.T) {
	base := shuffleFixture()
	for seed := int64(0); seed < 2000; seed++ {
		exts := shuffleFixture()
		ShuffleChromeTLSExtensionsWithSeed(exts, seed)
		for i := range base {
			if !positionInvariantExtension(base[i]) {
				continue
			}
			if fmt.Sprintf("%T", exts[i]) != fmt.Sprintf("%T", base[i]) {
				t.Fatalf("seed %d: pinned %T at index %d was replaced by %T",
					base[i], i, exts[i], seed)
			}
		}
	}
}

// A movable extension sits at its canonical index no more often than any
// other, which is the property the declined-swap version does not have.
//
// The band is enormously wider than the sampling noise on purpose. At 20000
// samples the standard error on a 6.67 percent rate is about 0.18 points, so
// this cannot flake; the defect it catches is nearly double the expectation.
func TestShuffleIsUnbiased(t *testing.T) {
	const samples = 20000

	base := shuffleFixture()
	movable := movableIndices(base)
	uniform := 1 / float64(len(movable))
	low, high := uniform*0.65, uniform*1.35

	home := make(map[int]int, len(movable))
	for seed := int64(0); seed < samples; seed++ {
		exts := shuffleFixture()
		ShuffleChromeTLSExtensionsWithSeed(exts, seed)
		for _, i := range movable {
			if fmt.Sprintf("%T", exts[i]) == fmt.Sprintf("%T", base[i]) {
				home[i]++
			}
		}
	}
	for _, i := range movable {
		rate := float64(home[i]) / samples
		if rate < low || rate > high {
			t.Errorf("%T at index %d stayed put %.2f%% of the time; want near "+
				"%.2f%%, allowed %.2f%% to %.2f%%",
				base[i], i, 100*rate, 100*uniform, 100*low, 100*high)
		}
	}
}

// Every movable extension reaches every movable slot. This is the structural
// half: a permutation restricted to a subset of the slots would satisfy the
// rate test above and still never produce some orders.
func TestShuffleReachesEveryMovableSlot(t *testing.T) {
	base := shuffleFixture()
	movable := movableIndices(base)

	seen := make(map[string]map[int]bool)
	for _, i := range movable {
		seen[fmt.Sprintf("%T", base[i])] = map[int]bool{}
	}
	for seed := int64(0); seed < 20000; seed++ {
		exts := shuffleFixture()
		ShuffleChromeTLSExtensionsWithSeed(exts, seed)
		for _, i := range movable {
			name := fmt.Sprintf("%T", exts[i])
			if m, ok := seen[name]; ok {
				m[i] = true
			}
		}
	}
	for name, slots := range seen {
		if len(slots) != len(movable) {
			t.Errorf("%s reached %d of %d movable slots", name, len(slots), len(movable))
		}
	}
}

// Two different seeds give two different orders, and one seed always gives the
// same order. The seeded entrypoint exists so a session can hold one order
// across its connections.
func TestSeededShuffleIsStableAndVaries(t *testing.T) {
	order := func(seed int64) string {
		exts := shuffleFixture()
		ShuffleChromeTLSExtensionsWithSeed(exts, seed)
		s := ""
		for _, e := range exts {
			s += fmt.Sprintf("%T,", e)
		}
		return s
	}
	if order(7) != order(7) {
		t.Error("the same seed gave two different orders")
	}
	distinct := map[string]bool{}
	for seed := int64(0); seed < 50; seed++ {
		distinct[order(seed)] = true
	}
	if len(distinct) < 40 {
		t.Errorf("50 seeds produced only %d distinct orders", len(distinct))
	}
}

// The cookie echoed in the second ClientHello after a HelloRetryRequest goes
// into the permutable middle: never ahead of the leading GREASE extension, and
// never behind the trailing run of pinned ones.
//
// The old range was a uniform index from zero, so roughly one retried
// handshake in the number of extensions put the cookie at index 0, ahead of
// the leading GREASE. No browser emits that, and unlike most divergences the
// server elicits it directly by sending a HelloRetryRequest.
func TestCookieSpliceRange(t *testing.T) {
	psk := &UtlsPreSharedKeyExtension{}

	for _, tc := range []struct {
		name    string
		exts    []TLSExtension
		lo, hi  int
		comment string
	}{
		{
			name: "chrome shaped",
			exts: shuffleFixture(),
			lo:   1, hi: 16,
			comment: "one leading GREASE, then a trailing GREASE and padding",
		},
		{
			name: "with pre_shared_key last",
			exts: append(shuffleFixture(), psk),
			lo:   1, hi: 16,
			comment: "the extra pinned extension must not move the range; " +
				"a constant offset gets this length wrong",
		},
		{
			name: "no pinned extensions",
			exts: []TLSExtension{&SNIExtension{}, &ALPNExtension{}},
			lo:   0, hi: 2,
		},
		{
			name: "everything pinned",
			exts: []TLSExtension{&UtlsGREASEExtension{}, &UtlsPaddingExtension{}},
			lo:   1, hi: 1,
			comment: "no real spec looks like this; the cookie still must not " +
				"go ahead of the leading GREASE",
		},
		{
			name:    "empty",
			exts:    nil,
			lo:      0,
			hi:      0,
			comment: "must not produce a negative range",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi := cookieSpliceRange(tc.exts)
			if lo != tc.lo || hi != tc.hi {
				t.Fatalf("range = [%d,%d], want [%d,%d]; %s", lo, hi, tc.lo, tc.hi, tc.comment)
			}
			if lo > hi {
				t.Fatalf("range [%d,%d] is empty", lo, hi)
			}
			// Every index in the range has to be a legal home for the cookie:
			// after any leading pinned extension, before any trailing ones.
			for idx := lo; idx <= hi; idx++ {
				if idx > 0 && idx <= len(tc.exts) {
					if idx < len(tc.exts) && positionInvariantExtension(tc.exts[idx-1]) && idx-1 >= hi {
						t.Fatalf("index %d lands behind a pinned extension", idx)
					}
				}
				if idx == 0 && len(tc.exts) > 0 && positionInvariantExtension(tc.exts[0]) {
					t.Fatalf("index 0 puts the cookie ahead of a pinned %T", tc.exts[0])
				}
			}
		})
	}
}

// extOrder is the extension type sequence a spec would put on the wire.
func extOrder(t *testing.T, id ClientHelloID, seed int64) string {
	t.Helper()
	spec, err := UTLSIdToSpecWithSeed(id, seed)
	if err != nil {
		t.Fatalf("UTLSIdToSpecWithSeed(%+v): %v", id, err)
	}
	var b strings.Builder
	for _, e := range spec.Extensions {
		out := make([]byte, e.Len())
		if _, err := e.Read(out); err != nil && err != io.EOF {
			t.Fatalf("reading an extension: %v", err)
		}
		if len(out) >= 2 {
			fmt.Fprintf(&b, "%d,", int(out[0])<<8|int(out[1]))
		}
	}
	return b.String()
}

// Only Chromium clients permute their extensions.
//
// This asserts at the UTLSIdToSpecWithSeed level deliberately. The shuffle
// tests above call ShuffleChromeTLSExtensionsWithSeed directly, so they pass
// whatever that function is or is not applied to, and cannot catch a gate that
// is too broad or too narrow.
//
// Measured against a real CriOS/151 capture, whose extension sequence
// 0-23-65281-10-11-16-5-13-18-51-45-43-27 is this file's canonical Safari 18
// order entry for entry, while two of our own connections produced two
// different sequences.
func TestOnlyChromiumPermutesExtensions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      ClientHelloID
		permute bool
	}{
		{"chrome", HelloChrome_133, true},
		{"chrome 143", HelloChrome_143_Windows, true},
		{"safari", HelloSafari_18, false},
		{"ios", HelloIOS_18, false},
		{"ios QUIC", HelloIOS_18_QUIC, false},
		{"firefox", HelloFirefox_120, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Several seeds, because two orders can coincide by chance but six
			// cannot.
			seeds := []int64{1, 7, 99, 4242, 123456, 987654321}
			orders := map[string]bool{}
			for _, s := range seeds {
				orders[extOrder(t, tc.id, s)] = true
			}
			if tc.permute {
				if len(orders) < 4 {
					t.Errorf("%d seeds produced only %d distinct extension orders; "+
						"a Chromium client permutes, so nearly every seed should differ",
						len(seeds), len(orders))
				}
				return
			}
			if len(orders) != 1 {
				t.Errorf("%d seeds produced %d distinct extension orders; this "+
					"client does not permute, so every connection must carry the "+
					"same canonical sequence. A real capture of it has exactly one "+
					"JA3 and ours would have 6.2e9", len(seeds), len(orders))
			}
		})
	}
}

// And the canonical order a non-permuting client keeps is the one its parrot
// declares, not some arbitrary fixed shuffle of it.
//
// The real CriOS/151 capture sent 0,23,65281,10,11,16,5,13,18,51,45,43,27
// between its two GREASE extensions.
func TestSafariKeepsItsCanonicalOrder(t *testing.T) {
	got := extOrder(t, HelloIOS_18, 12345)
	const want = "0,23,65281,10,11,16,5,13,18,51,45,43,27,"
	if !strings.Contains(got, want) {
		t.Errorf("iOS 18 extension order is\n  %s\nwant it to contain the captured\n  %s",
			got, want)
	}
}
