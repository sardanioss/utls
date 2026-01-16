// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"slices"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

type ClientHelloBuildStatus int

const NotBuilt ClientHelloBuildStatus = 0
const BuildByUtls ClientHelloBuildStatus = 1
const BuildByGoTLS ClientHelloBuildStatus = 2

type UConn struct {
	*Conn

	Extensions        []TLSExtension
	ClientHelloID     ClientHelloID
	sessionController *sessionController

	clientHelloBuildStatus ClientHelloBuildStatus
	clientHelloSpec        *ClientHelloSpec

	HandshakeState PubClientHandshakeState

	greaseSeed [ssl_grease_last_index]uint16

	omitSNIExtension bool

	// skipResumptionOnNilExtension is copied from `Config.PreferSkipResumptionOnNilExtension`.
	//
	// By default, if ClientHelloSpec is predefined or utls-generated (as opposed to HelloCustom), this flag will be updated to true.
	skipResumptionOnNilExtension bool

	// certCompressionAlgs represents the set of advertised certificate compression
	// algorithms, as specified in the ClientHello. This is only relevant client-side, for the
	// server certificate. All other forms of certificate compression are unsupported.
	certCompressionAlgs []CertCompressionAlgo

	// ech extension is a shortcut to the ECH extension in the Extensions slice if there is one.
	ech ECHExtension

	// echCtx is the echContex returned by makeClientHello()
	echCtx *echClientContext

	// pskBinderKey is stored after loadSession for use in ECH+PSK PROPER mode
	pskBinderKey []byte
	// pskCipherSuite is stored after loadSession for use in ECH+PSK PROPER mode
	pskCipherSuite *cipherSuiteTLS13
}

// UClient returns a new uTLS client, with behavior depending on clientHelloID.
// Config CAN be nil, but make sure to eventually specify ServerName.
func UClient(conn net.Conn, config *Config, clientHelloID ClientHelloID) *UConn {
	if config == nil {
		config = &Config{}
	}
	tlsConn := Conn{conn: conn, config: config, isClient: true}
	handshakeState := PubClientHandshakeState{C: &tlsConn, Hello: &PubClientHelloMsg{}}
	uconn := UConn{Conn: &tlsConn, ClientHelloID: clientHelloID, HandshakeState: handshakeState}
	uconn.HandshakeState.uconn = &uconn
	uconn.handshakeFn = uconn.clientHandshake
	uconn.sessionController = newSessionController(&uconn)
	uconn.utls.sessionController = uconn.sessionController
	uconn.skipResumptionOnNilExtension = config.PreferSkipResumptionOnNilExtension || clientHelloID.Client != helloCustom
	return &uconn
}

// BuildHandshakeState behavior varies based on ClientHelloID and
// whether it was already called before.
// If HelloGolang:
//
//	[only once] make default ClientHello and overwrite existing state
//
// If any other mimicking ClientHelloID is used:
//
//	[only once] make ClientHello based on ID and overwrite existing state
//	[each call] apply uconn.Extensions config to internal crypto/tls structures
//	[each call] marshal ClientHello.
//
// BuildHandshakeState is automatically called before uTLS performs handshake,
// and should only be called explicitly to inspect/change fields of
// default/mimicked ClientHello.
// With the excpetion of session ticket and psk extensions, which cannot be changed
// after calling BuildHandshakeState, all other fields can be modified.
func (uconn *UConn) BuildHandshakeState() error {
	return uconn.buildHandshakeState(true)
}

// BuildHandshakeStateWithoutSession is the same as BuildHandshakeState, but does not
// set the session. This is only useful when you want to inspect the ClientHello before
// setting the session manually through SetSessionTicketExtension or SetPSKExtension.
// BuildHandshakeState is automatically called before uTLS performs handshake.
func (uconn *UConn) BuildHandshakeStateWithoutSession() error {
	return uconn.buildHandshakeState(false)
}

func (uconn *UConn) buildHandshakeState(loadSession bool) error {
	if uconn.ClientHelloID == HelloGolang {
		if uconn.clientHelloBuildStatus == BuildByGoTLS {
			return nil
		}
		uAssert(uconn.clientHelloBuildStatus == NotBuilt, "BuildHandshakeState failed: invalid call, client hello has already been built by utls")

		// use default Golang ClientHello.
		hello, keySharePrivate, ech, err := uconn.makeClientHello()
		if err != nil {
			return err
		}

		uconn.HandshakeState.Hello = hello.getPublicPtr()
		uconn.HandshakeState.State13.KeyShareKeys = keySharePrivate.ToPublic()
		uconn.HandshakeState.C = uconn.Conn
		uconn.echCtx = ech
		uconn.clientHelloBuildStatus = BuildByGoTLS
	} else {
		uAssert(uconn.clientHelloBuildStatus == BuildByUtls || uconn.clientHelloBuildStatus == NotBuilt, "BuildHandshakeState failed: invalid call, client hello has already been built by go-tls")
		if uconn.clientHelloBuildStatus == NotBuilt {
			err := uconn.applyPresetByID(uconn.ClientHelloID)
			if err != nil {
				return err
			}
			if uconn.omitSNIExtension {
				uconn.removeSNIExtension()
			}
		}

		err := uconn.ApplyConfig()
		if err != nil {
			return err
		}

		if loadSession {
			err = uconn.uLoadSession()
			if err != nil {
				return err
			}
		}

		// Only marshal ClientHello if not already built
		// This prevents overwriting ech.innerHello (with PSK data) on subsequent calls
		if uconn.clientHelloBuildStatus != BuildByUtls {
			err = uconn.MarshalClientHello()
			if err != nil {
				return err
			}
		}

		if loadSession {
			uconn.uApplyPatch()
			uconn.sessionController.finalCheck()
		}

		// Always mark as BuildByUtls after MarshalClientHello succeeds
		uconn.clientHelloBuildStatus = BuildByUtls
	}
	return nil
}

func (uconn *UConn) uLoadSession() error {
	if cfg := uconn.config; cfg.SessionTicketsDisabled || cfg.ClientSessionCache == nil {
		return nil
	}
	shouldLoad := uconn.sessionController.shouldLoadSession()
	switch shouldLoad {
	case shouldReturn:
		// Nothing to do
	case shouldSetTicket:
		uconn.sessionController.setSessionTicketToUConn()
	case shouldSetPsk:
		uconn.sessionController.setPskToUConn()
	case shouldLoad:
		hello := uconn.HandshakeState.Hello.getPrivatePtr()
		uconn.sessionController.utlsAboutToLoadSession()
		session, earlySecret, binderKey, err := uconn.loadSession(hello)
		if session == nil || err != nil {
			return err
		}
		if session.version == VersionTLS12 {
			// We use the session ticket extension for tls 1.2 session resumption
			uconn.sessionController.initSessionTicketExt(session, hello.sessionTicket)
			uconn.sessionController.setSessionTicketToUConn()
		} else {
			uconn.sessionController.initPskExt(session, earlySecret, binderKey, hello.pskIdentities)
			// Only propagate PSK if initPskExt succeeded (i.e., pskExtension was present and initialized)
			if uconn.sessionController.shouldUpdateBinders() {
				uconn.sessionController.setPskToUConn()
				// Store for ECH+PSK PROPER mode
				uconn.pskBinderKey = binderKey
				uconn.pskCipherSuite = cipherSuiteTLS13ByID(session.cipherSuite)
			}
		}
	}

	return nil
}

func (uconn *UConn) uApplyPatch() {
	helloLen := len(uconn.HandshakeState.Hello.Raw)
	if uconn.sessionController.shouldUpdateBinders() {
		uconn.sessionController.updateBinders()
		uconn.sessionController.setPskToUConn()
	}
	uAssert(helloLen == len(uconn.HandshakeState.Hello.Raw), "tls: uApplyPatch Failed: the patch should never change the length of the marshaled clientHello")
}

func (uconn *UConn) DidTls12Resume() bool {
	return uconn.didResume
}

// SetSessionState sets the session ticket, which may be preshared or fake.
// If session is nil, the body of session ticket extension will be unset,
// but the extension itself still MAY be present for mimicking purposes.
// Session tickets to be reused - use same cache on following connections.
//
// Deprecated: This method is deprecated in favor of SetSessionTicketExtension,
// as it only handles session override of TLS 1.2
func (uconn *UConn) SetSessionState(session *ClientSessionState) error {
	sessionTicketExt := &SessionTicketExtension{Initialized: true}
	if session != nil {
		sessionTicketExt.Ticket = session.session.ticket
		sessionTicketExt.Session = session.session
	}
	return uconn.SetSessionTicketExtension(sessionTicketExt)
}

// SetSessionTicket sets the session ticket extension.
// If extension is nil, this will be a no-op.
func (uconn *UConn) SetSessionTicketExtension(sessionTicketExt ISessionTicketExtension) error {
	if uconn.config.SessionTicketsDisabled || uconn.config.ClientSessionCache == nil {
		return fmt.Errorf("tls: SetSessionTicketExtension failed: session is disabled")
	}
	if sessionTicketExt == nil {
		return nil
	}
	return uconn.sessionController.overrideSessionTicketExt(sessionTicketExt)
}

// SetPskExtension sets the psk extension for tls 1.3 resumption. This is a no-op if the psk is nil.
func (uconn *UConn) SetPskExtension(pskExt PreSharedKeyExtension) error {
	if uconn.config.SessionTicketsDisabled || uconn.config.ClientSessionCache == nil {
		return fmt.Errorf("tls: SetPskExtension failed: session is disabled")
	}
	if pskExt == nil {
		return nil
	}

	uconn.HandshakeState.Hello.TicketSupported = true
	return uconn.sessionController.overridePskExt(pskExt)
}

// If you want session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionCache(cache ClientSessionCache) {
	uconn.config.ClientSessionCache = cache
	uconn.HandshakeState.Hello.TicketSupported = true
}

// SetClientRandom sets client random explicitly.
// BuildHandshakeFirst() must be called before SetClientRandom.
// r must to be 32 bytes long.
func (uconn *UConn) SetClientRandom(r []byte) error {
	if len(r) != 32 {
		return errors.New("Incorrect client random length! Expected: 32, got: " + strconv.Itoa(len(r)))
	} else {
		uconn.HandshakeState.Hello.Random = make([]byte, 32)
		copy(uconn.HandshakeState.Hello.Random, r)
		return nil
	}
}

func (uconn *UConn) SetSNI(sni string) {
	hname := hostnameInSNI(sni)
	uconn.config.ServerName = hname
	for _, ext := range uconn.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
}

// RemoveSNIExtension removes SNI from the list of extensions sent in ClientHello
// It returns an error when used with HelloGolang ClientHelloID
func (uconn *UConn) RemoveSNIExtension() error {
	if uconn.ClientHelloID == HelloGolang {
		return fmt.Errorf("cannot call RemoveSNIExtension on a UConn with a HelloGolang ClientHelloID")
	}
	uconn.omitSNIExtension = true
	return nil
}

func (uconn *UConn) removeSNIExtension() {
	filteredExts := make([]TLSExtension, 0, len(uconn.Extensions))
	for _, e := range uconn.Extensions {
		if _, ok := e.(*SNIExtension); !ok {
			filteredExts = append(filteredExts, e)
		}
	}
	uconn.Extensions = filteredExts
}

// Handshake runs the client handshake using given clientHandshakeState
// Requires hs.hello, and, optionally, hs.session to be set.
func (c *UConn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server handshake
// protocol if it has not yet been run.
//
// The provided Context must be non-nil. If the context is canceled before
// the handshake is complete, the handshake is interrupted and an error is returned.
// Once the handshake has completed, cancellation of the context will not affect the
// connection.
func (c *UConn) HandshakeContext(ctx context.Context) error {
	// Delegate to unexported method for named return
	// without confusing documented signature.
	return c.handshakeContext(ctx)
}

func (c *UConn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if c.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	// Start the "interrupter" goroutine, if this context might be canceled.
	// (The background context cannot).
	//
	// The interrupter goroutine waits for the input context to be done and
	// closes the connection if this happens before the function returns.
	if c.quic != nil {
		c.quic.cancelc = handshakeCtx.Done()
		c.quic.cancel = cancel
	} else if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	// [uTLS section begins]
	if c.isClient {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
	}
	// [uTLS section ends]
	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	if c.quic != nil {
		if c.handshakeErr == nil {
			c.quicHandshakeComplete()
			// Provide the 1-RTT read secret now that the handshake is complete.
			// The QUIC layer MUST NOT decrypt 1-RTT packets prior to completing
			// the handshake (RFC 9001, Section 5.7).
			c.quicSetReadSecret(QUICEncryptionLevelApplication, c.cipherSuite, c.in.trafficSecret)
		} else {
			var a alert
			c.out.Lock()
			if !errors.As(c.out.err, &a) {
				a = alertInternalError
			}
			c.out.Unlock()
			// Return an error which wraps both the handshake error and
			// any alert error we may have sent, or alertInternalError
			// if we didn't send an alert.
			// Truncate the text of the alert to 0 characters.
			c.handshakeErr = fmt.Errorf("%w%.0w", c.handshakeErr, AlertError(a))
		}
		close(c.quic.blockedc)
		close(c.quic.signalc)
	}

	return c.handshakeErr
}

// Copy-pasted from tls.Conn in its entirety. But c.Handshake() is now utls' one, not tls.
// Write writes data to the connection.
func (c *UConn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			defer c.activeCall.Add(-2)
			break
		}
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.isHandshakeComplete.Load() {
		return 0, alertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	// SSL 3.0 and TLS 1.0 are susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && c.vers <= VersionTLS10 {
		if _, ok := c.out.cipher.(cipher.BlockMode); ok {
			n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.out.setErrorLocked(err)
}

func (uconn *UConn) ApplyConfig() error {
	for _, ext := range uconn.Extensions {
		err := ext.writeToUConn(uconn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uconn *UConn) extensionsList() []uint16 {

	outerExts := []uint16{}
	for _, ext := range uconn.Extensions {
		buffer := cryptobyte.String(make([]byte, 2000))
		ext.Read(buffer)
		var extension uint16
		buffer.ReadUint16(&extension)
		// Exclude supported_versions (43) - inner hello MUST have its own
		// supported_versions with only TLS 1.3 per ECH spec
		if extension == extensionSupportedVersions {
			continue
		}
		outerExts = append(outerExts, extension)
	}
	return outerExts
}

func (uconn *UConn) computeAndUpdateOuterECHExtension(inner *clientHelloMsg, ech *echClientContext, useKey bool) error {
	// Use the current extensions list
	return uconn.computeAndUpdateOuterECHExtensionWithOuterExts(inner, ech, useKey, uconn.extensionsList(), nil)
}

func (uconn *UConn) computeAndUpdateOuterECHExtensionWithOuterExts(inner *clientHelloMsg, ech *echClientContext, useKey bool, outerExts []uint16, pskExt *UtlsPreSharedKeyExtension) error {
	// This function is mostly copied from
	// https://github.com/sardanioss/utls/blob/e430876b1d82fdf582efc57f3992d448e7ab3d8a/ech.go#L408

	// For PSK requests, Chrome includes early_data in ech_outer_extensions
	// Only filter early_data for non-PSK requests
	if pskExt == nil {
		filteredOuterExts := make([]uint16, 0, len(outerExts))
		for _, extType := range outerExts {
			if extType != extensionEarlyData {
				filteredOuterExts = append(filteredOuterExts, extType)
			}
		}
		outerExts = filteredOuterExts
	}

	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
	}

	encodedInner, err := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), outerExts)
	if err != nil {
		return err
	}

	// Store encodedInnerHello for later use
	// expandedInnerHello will be stored AFTER the outer hello is marshaled, so we can
	// decode it properly using decodeInnerClientHello to match what the server computes
	ech.encodedInnerHello = encodedInner

	encryptedLen := len(encodedInner) + 16
	outerECHExt, err := generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, make([]byte, encryptedLen))
	if err != nil {
		return err
	}

	echExtIdx := slices.IndexFunc(uconn.Extensions, func(ext TLSExtension) bool {
		_, ok := ext.(EncryptedClientHelloExtension)
		return ok
	})
	if echExtIdx < 0 {
		return fmt.Errorf("extension satisfying EncryptedClientHelloExtension not present")
	}
	oldExt := uconn.Extensions[echExtIdx]

	uconn.Extensions[echExtIdx] = &GenericExtension{
		Id:   extensionEncryptedClientHello,
		Data: outerECHExt,
	}

	// Chrome keeps early_data in outer hello, and inner references it via ech_outer_extensions
	// Do NOT remove FakeEarlyDataExtension from outer hello

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	serializedOuter := uconn.HandshakeState.Hello.Raw
	serializedOuter = serializedOuter[4:]

	// NOTE: PSK binder fix moved to the end of this function, after expandedInnerHello is stored.
	// This ensures we calculate the binder using the FINAL expanded form that matches what
	// the server will decode.

	// Handle PSK mode: PROPER (default) vs FALLBACK
	// PROPER mode: PSK in inner hello, ECH maintained during session resumption
	// FALLBACK mode: PSK in outer only, ECH bypassed (set UTLS_ECH_PSK_FALLBACK=1 to use)
	useFallbackMode := os.Getenv("UTLS_ECH_PSK_FALLBACK") != ""
	if pskExt != nil && pskExt.cipherSuite != nil && len(pskExt.BinderKey) > 0 {
		if useFallbackMode {
			// FALLBACK mode: PSK in outer only, store outer for early traffic
			outerWithHeader := make([]byte, 4+len(serializedOuter))
			outerWithHeader[0] = typeClientHello // 0x01
			outerWithHeader[1] = byte(len(serializedOuter) >> 16)
			outerWithHeader[2] = byte(len(serializedOuter) >> 8)
			outerWithHeader[3] = byte(len(serializedOuter))
			copy(outerWithHeader[4:], serializedOuter)

			ech.expandedInnerHello = outerWithHeader
			ech.pskInOuterOnly = true
		}
		// PROPER mode (default): pskInOuterOnly stays false
		// encodedInnerHello and expandedInnerHello are already stored unconditionally above
	}

	// CRITICAL: Fix PSK binder BEFORE Seal (HPKE sequence number increments per Seal)
	// The binder must be calculated over the EXPANDED inner hello format, which is what
	// the server will verify against. We can only call Seal ONCE per HPKE context.
	if len(inner.pskIdentities) > 0 && uconn.pskCipherSuite != nil && len(uconn.pskBinderKey) > 0 {
		// Parse outer from serializedOuter to decode inner
		outerForDecode := new(clientHelloMsg)
		// Need to add header back for unmarshal
		outerWithHeader := make([]byte, len(serializedOuter)+4)
		outerWithHeader[0] = typeClientHello
		outerWithHeader[1] = byte(len(serializedOuter) >> 16)
		outerWithHeader[2] = byte(len(serializedOuter) >> 8)
		outerWithHeader[3] = byte(len(serializedOuter))
		copy(outerWithHeader[4:], serializedOuter)

		if outerForDecode.unmarshal(outerWithHeader) {
			// Decode to get expanded form WITH raw bytes
			decodedInner, reconBytes, decodeErr := decodeInnerClientHelloWithRaw(outerForDecode, encodedInner)
			if decodeErr == nil && len(decodedInner.pskBinders) > 0 {
				// Calculate correct binder using raw reconBytes (NOT re-marshaled struct)
				// Per RFC 8446 Section 4.2.11.2, strip binders from the end but keep length fields intact
				bindersLen := 2 // uint16 length prefix for binders list
				for _, binder := range decodedInner.pskBinders {
					bindersLen += 1 + len(binder) // uint8 length prefix + binder data
				}
				helloBytes := reconBytes[:len(reconBytes)-bindersLen]

				transcript := uconn.pskCipherSuite.hash.New()
				transcript.Write(helloBytes)
				correctBinder := uconn.pskCipherSuite.finishedHash(uconn.pskBinderKey, transcript)

				// Check if binder matches
				currentBinder := decodedInner.pskBinders[0]
				if !bytes.Equal(currentBinder, correctBinder) {
					// Update inner's binder and re-encode
					inner.pskBinders[0] = correctBinder
					inner.original = nil
					newEncodedInner, encodeErr := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), outerExts)
					if encodeErr == nil {
						encodedInner = newEncodedInner
						ech.encodedInnerHello = encodedInner

						// Re-decode and store raw expandedInnerHello bytes
						_, fixedReconBytes, decodeErr := decodeInnerClientHelloWithRaw(outerForDecode, encodedInner)
						if decodeErr == nil && fixedReconBytes != nil {
							ech.expandedInnerHello = fixedReconBytes
							ech.preSealExpandedInner = fixedReconBytes // Store for comparison
						}
					}
				}
			}
		}
	}

	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		return err
	}

	outerECHExt, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, encryptedInner)
	if err != nil {
		return err
	}
	uconn.Extensions[echExtIdx] = &GenericExtension{
		Id:   extensionEncryptedClientHello,
		Data: outerECHExt,
	}

	// Chrome keeps early_data in outer hello for PSK, and inner references it via ech_outer_extensions
	// Do NOT remove FakeEarlyDataExtension from outer hello

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	// CRITICAL: Store expandedInnerHello by decoding the encodedInner using the outer hello
	// This ensures we get the exact same bytes the server will compute when it decodes
	// First, unmarshal the raw outer hello into a clientHelloMsg
	outerHello := new(clientHelloMsg)
	if outerHello.unmarshal(uconn.HandshakeState.Hello.Raw) {
		decodedInner, decodeErr := decodeInnerClientHello(outerHello, encodedInner)
		if decodeErr == nil {
			decodedBytes, marshalErr := decodedInner.marshal()
			if marshalErr == nil {
				ech.expandedInnerHello = decodedBytes
			}
		}
	}

	// NOTE: POST-SEAL binder fix is DISABLED because HPKE sequence number increments per Seal.
	// The binder fix is now done PRE-SEAL (before the Seal call above).

	uconn.Extensions[echExtIdx] = oldExt
	return nil
}


func (uconn *UConn) MarshalClientHello() error {
	// Ensure ApplyConfig is called to populate HandshakeState.Hello fields from extensions
	// This is needed when ApplyPreset is called directly without going through BuildHandshakeState
	if err := uconn.ApplyConfig(); err != nil {
		return err
	}

	if len(uconn.config.EncryptedClientHelloConfigList) > 0 {
		inner, _, ech, err := uconn.makeClientHello()
		if err != nil {
			return err
		}

		// Copy cipher suites from outer hello (Chrome fingerprint) to inner hello
		// This is CRITICAL - inner hello must have same cipher suites as outer for fingerprint matching
		inner.cipherSuites = uconn.HandshakeState.Hello.CipherSuites

		// copy ALL extensions from outer hello to inner hello
		// This ensures PSK binder calculation matches what server computes after reconstructing inner hello
		// The server reconstructs ClientHelloInner by expanding ech_outer_extensions references
		inner.keyShares = KeyShares(uconn.HandshakeState.Hello.KeyShares).ToPrivate()
		inner.supportedSignatureAlgorithms = uconn.HandshakeState.Hello.SupportedSignatureAlgorithms
		inner.supportedSignatureAlgorithmsCert = uconn.HandshakeState.Hello.SupportedSignatureAlgorithmsCert
		inner.sessionId = uconn.HandshakeState.Hello.SessionId
		inner.supportedCurves = uconn.HandshakeState.Hello.SupportedCurves
		inner.pskModes = uconn.HandshakeState.Hello.PskModes
		inner.alpnProtocols = uconn.HandshakeState.Hello.AlpnProtocols
		inner.earlyData = uconn.HandshakeState.Hello.EarlyData
		inner.ticketSupported = uconn.HandshakeState.Hello.TicketSupported
		inner.secureRenegotiationSupported = uconn.HandshakeState.Hello.SecureRenegotiationSupported
		inner.secureRenegotiation = uconn.HandshakeState.Hello.SecureRenegotiation

		// NOTE: ECH spec says early_data "MUST NOT" be in outer hello, but Chrome
		// includes early_data in outer hello for PSK/0-RTT case and it works.
		// Without early_data in outer, QUIC 0-RTT fails because server doesn't
		// know to accept early data. Keeping early_data in both inner and outer.
		// uconn.HandshakeState.Hello.EarlyData = false // DISABLED - Chrome doesn't do this

		// For PSK with ECH: get PSK data from the extension and recalculate binders for inner hello
		// The outer hello's binders were calculated over the outer transcript, but the server
		// will verify binders against the inner ClientHello transcript after decrypting ECH
		var pskExt *UtlsPreSharedKeyExtension
		for _, ext := range uconn.Extensions {
			if e, ok := ext.(*UtlsPreSharedKeyExtension); ok {
				pskExt = e
				break
			}
		}

		// Get QUIC transport parameters from the extension (not from PubClientHelloMsg field)
		// The extension contains the actual marshaled transport parameters
		for _, ext := range uconn.Extensions {
			if qtpExt, ok := ext.(*QUICTransportParametersExtension); ok {
				// Marshal the extension to get the transport parameters data
				extLen := qtpExt.Len()
				if extLen > 4 { // 2 bytes for type + 2 bytes for length
					buf := make([]byte, extLen)
					qtpExt.Read(buf)
					// Skip the 4-byte header (type + length), get the actual data
					inner.quicTransportParameters = buf[4:]
				}
				break
			}
		}

		// For ECH + PSK (Chrome behavior):
		// 1. Keep REAL PSK in outer ClientHello (server uses this directly)
		// 2. Do NOT put PSK in inner ClientHello (keeps ECH payload small like Chrome)
		// This deviates from ECH spec but matches Chrome's real-world behavior.
		// See chrome_reference_data.md: Chrome's ECH payload is 240 bytes for both PSK and non-PSK.
		// Save the outer extensions list for encoding the inner hello
		var outerExtsList []uint16
		if pskExt != nil && pskExt.cipherSuite != nil && len(pskExt.BinderKey) > 0 && len(pskExt.Identities) > 0 {
			// Check for PROPER mode (default) vs FALLBACK mode
			// PROPER mode: PSK in inner hello, ECH maintained
			// FALLBACK mode: PSK in outer only, ECH bypassed (set UTLS_ECH_PSK_FALLBACK=1)
			useFallbackModeInner := os.Getenv("UTLS_ECH_PSK_FALLBACK") != ""

			if !useFallbackModeInner {
				// PROPER MODE: Copy PSK to inner hello for true ECH+PSK
				inner.pskIdentities = make([]pskIdentity, len(pskExt.Identities))
				for i, id := range pskExt.Identities {
					inner.pskIdentities[i] = pskIdentity{
						label:               id.Label,
						obfuscatedTicketAge: id.ObfuscatedTicketAge,
					}
				}
				// Initialize binders with placeholder (correct size)
				inner.pskBinders = make([][]byte, len(pskExt.Binders))
				for i, b := range pskExt.Binders {
					inner.pskBinders[i] = make([]byte, len(b))
				}

				// Recalculate PSK binder for inner hello transcript
				// The binder must be computed over the inner hello, not the outer
				if uconn.pskCipherSuite != nil && len(uconn.pskBinderKey) > 0 {
					transcript := uconn.pskCipherSuite.hash.New()
					helloBytes, err := inner.marshalWithoutBinders()
					if err != nil {
						return err
					}
					transcript.Write(helloBytes)
					pskBinder := uconn.pskCipherSuite.finishedHash(uconn.pskBinderKey, transcript)
					inner.pskBinders[0] = pskBinder
				}

				// Per ECH spec (draft-ietf-tls-esni), the outer PSK MUST use GREASE values
				// when ECH is offered with PSK in inner. The outer hello should have
				// random PSK identities and binders of the same lengths as the real ones.
				for i := range pskExt.Identities {
					// Generate random label with same length
					randomLabel := make([]byte, len(pskExt.Identities[i].Label))
					_, _ = io.ReadFull(uconn.config.rand(), randomLabel)
					pskExt.Identities[i].Label = randomLabel
					// Generate random obfuscated_ticket_age
					var randomAge [4]byte
					_, _ = io.ReadFull(uconn.config.rand(), randomAge[:])
					pskExt.Identities[i].ObfuscatedTicketAge = uint32(randomAge[0])<<24 | uint32(randomAge[1])<<16 | uint32(randomAge[2])<<8 | uint32(randomAge[3])
				}
				for i := range pskExt.Binders {
					// Generate random binder with same length
					randomBinder := make([]byte, len(pskExt.Binders[i]))
					_, _ = io.ReadFull(uconn.config.rand(), randomBinder)
					pskExt.Binders[i] = randomBinder
				}
				// Prevent PatchBuiltHello from recalculating binders (would overwrite GREASE)
				pskExt.SkipBinderPatching = true
			}
			// FALLBACK (Chrome-style): Do NOT put PSK in inner hello

			// Save outer extensions list for encoding inner hello
			outerExtsList = uconn.extensionsList()

			// In PROPER mode, EXCLUDE PSK (type 41) from ech_outer_extensions
			// The PSK with inner binder must stay in inner hello, not be compressed
			// Also ALWAYS exclude ECH (type 0xfe0d = 65037) - the inner hello has its own ECH marker
			// (value 0x01 for inner), not the full ECH payload from outer
			filtered := make([]uint16, 0, len(outerExtsList))
			for _, ext := range outerExtsList {
				// Filter out ECH (0xfe0d = 65037) - inner has its own marker
				if ext == 65037 {
					continue
				}
				// In PROPER mode (default), also filter out PSK (41)
				if !useFallbackModeInner && ext == 41 {
					continue
				}
				filtered = append(filtered, ext)
			}
			outerExtsList = filtered
		}

		ech.innerHello = inner

		// For ECH, the outer hello's SNI must be the ECH public name (from ECH config)
		// Save the original SNI to restore after ECH computation if needed
		originalServerName := uconn.config.ServerName
		publicName := string(ech.config.PublicName)

		// Update outer SNI extension to use the ECH public name
		uconn.config.ServerName = publicName
		for _, ext := range uconn.Extensions {
			if sniExt, ok := ext.(*SNIExtension); ok {
				sniExt.ServerName = publicName
				break
			}
		}

		// Use the saved outerExtsList if available (computed before GREASE PSK replacement)
		// This ensures we encode the inner hello with the correct PSK extension type (41)
		// instead of the GREASE PSK which has type 0 when reading from buffer
		var echErr error
		if outerExtsList != nil {
			echErr = uconn.computeAndUpdateOuterECHExtensionWithOuterExts(inner, ech, true, outerExtsList, pskExt)
		} else {
			echErr = uconn.computeAndUpdateOuterECHExtension(inner, ech, true)
		}
		if echErr != nil {
			// Restore original server name on error
			uconn.config.ServerName = originalServerName
			return echErr
		}

		// Restore original server name for connection state
		// The outer hello is already serialized with the public name
		uconn.config.ServerName = originalServerName

		uconn.echCtx = ech
		return nil
	}

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	return nil

}

// MarshalClientHelloNoECH marshals ClientHello as if there was no
// ECH extension present.
func (uconn *UConn) MarshalClientHelloNoECH() error {
	hello := uconn.HandshakeState.Hello
	headerLength := 2 + 32 + 1 + len(hello.SessionId) +
		2 + len(hello.CipherSuites)*2 +
		1 + len(hello.CompressionMethods)

	extensionsLen := 0
	var paddingExt *UtlsPaddingExtension // reference to padding extension, if present
	for _, ext := range uconn.Extensions {
		if pe, ok := ext.(*UtlsPaddingExtension); !ok {
			// If not padding - just add length of extension to total length
			extensionsLen += ext.Len()
		} else {
			// If padding - process it later
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("multiple padding extensions")
			}
		}
	}

	if paddingExt != nil {
		// determine padding extension presence and length
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		extensionsLen += paddingExt.Len()
	}

	helloLen := headerLength
	if len(uconn.Extensions) > 0 {
		helloLen += 2 + extensionsLen // 2 bytes for extensions' length
	}

	helloBuffer := bytes.Buffer{}
	bufferedWriter := bufio.NewWriterSize(&helloBuffer, helloLen+4) // 1 byte for tls record type, 3 for length
	// We use buffered Writer to avoid checking write errors after every Write(): whenever first error happens
	// Write() will become noop, and error will be accessible via Flush(), which is called once in the end

	binary.Write(bufferedWriter, binary.BigEndian, typeClientHello)
	helloLenBytes := []byte{byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen)} // poor man's uint24
	binary.Write(bufferedWriter, binary.BigEndian, helloLenBytes)
	binary.Write(bufferedWriter, binary.BigEndian, hello.Vers)

	binary.Write(bufferedWriter, binary.BigEndian, hello.Random)

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.SessionId)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.SessionId)

	binary.Write(bufferedWriter, binary.BigEndian, uint16(len(hello.CipherSuites)<<1))
	for _, suite := range hello.CipherSuites {
		binary.Write(bufferedWriter, binary.BigEndian, suite)
	}

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.CompressionMethods)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.CompressionMethods)

	if len(uconn.Extensions) > 0 {
		binary.Write(bufferedWriter, binary.BigEndian, uint16(extensionsLen))
		for _, ext := range uconn.Extensions {
			if _, err := bufferedWriter.ReadFrom(ext); err != nil {
				return err
			}
		}
	}

	err := bufferedWriter.Flush()
	if err != nil {
		return err
	}

	if helloBuffer.Len() != 4+helloLen {
		return errors.New("utls: unexpected ClientHello length. Expected: " + strconv.Itoa(4+helloLen) +
			". Got: " + strconv.Itoa(helloBuffer.Len()))
	}

	hello.Raw = helloBuffer.Bytes()
	return nil
}

// get current state of cipher and encrypt zeros to get keystream
func (uconn *UConn) GetOutKeystream(length int) ([]byte, error) {
	zeros := make([]byte, length)

	if outCipher, ok := uconn.out.cipher.(cipher.AEAD); ok {
		// AEAD.Seal() does not mutate internal state, other ciphers might
		return outCipher.Seal(nil, uconn.out.seq[:], zeros, nil), nil
	}
	return nil, errors.New("could not convert OutCipher to cipher.AEAD")
}

// SetTLSVers sets min and max TLS version in all appropriate places.
// Function will use first non-zero version parsed in following order:
//  1. Provided minTLSVers, maxTLSVers
//  2. specExtensions may have SupportedVersionsExtension
//  3. [default] min = TLS 1.0, max = TLS 1.2
//
// Error is only returned if things are in clearly undesirable state
// to help user fix them.
func (uconn *UConn) SetTLSVers(minTLSVers, maxTLSVers uint16, specExtensions []TLSExtension) error {
	if minTLSVers == 0 && maxTLSVers == 0 {
		// if version is not set explicitly in the ClientHelloSpec, check the SupportedVersions extension
		supportedVersionsExtensionsPresent := 0
		for _, e := range specExtensions {
			switch ext := e.(type) {
			case *SupportedVersionsExtension:
				findVersionsInSupportedVersionsExtensions := func(versions []uint16) (uint16, uint16) {
					// returns (minVers, maxVers)
					minVers := uint16(0)
					maxVers := uint16(0)
					for _, vers := range versions {
						if isGREASEUint16(vers) {
							continue
						}
						if maxVers < vers || maxVers == 0 {
							maxVers = vers
						}
						if minVers > vers || minVers == 0 {
							minVers = vers
						}
					}
					return minVers, maxVers
				}

				supportedVersionsExtensionsPresent += 1
				minTLSVers, maxTLSVers = findVersionsInSupportedVersionsExtensions(ext.Versions)
				if minTLSVers == 0 && maxTLSVers == 0 {
					return fmt.Errorf("SupportedVersions extension has invalid Versions field")
				} // else: proceed
			}
		}
		switch supportedVersionsExtensionsPresent {
		case 0:
			// if mandatory for TLS 1.3 extension is not present, just default to 1.2
			minTLSVers = VersionTLS10
			maxTLSVers = VersionTLS12
		case 1:
		default:
			return fmt.Errorf("uconn.Extensions contains %v separate SupportedVersions extensions",
				supportedVersionsExtensionsPresent)
		}
	}

	if minTLSVers < VersionTLS10 || minTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as min version", minTLSVers)
	}

	if maxTLSVers < VersionTLS10 || maxTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as max version", maxTLSVers)
	}

	uconn.HandshakeState.Hello.SupportedVersions = makeSupportedVersions(minTLSVers, maxTLSVers)
	if uconn.config.EncryptedClientHelloConfigList == nil {
		uconn.config.MinVersion = minTLSVers
		uconn.config.MaxVersion = maxTLSVers
	}

	return nil
}

func (uconn *UConn) SetUnderlyingConn(c net.Conn) {
	uconn.Conn.conn = c
}

func (uconn *UConn) GetUnderlyingConn() net.Conn {
	return uconn.Conn.conn
}

// GetGREASESeed returns the GREASE seed used by this connection.
// This can be used to cache the seed and apply it to future connections
// via ClientHelloSpec.GREASESeed for consistent TLS fingerprints.
func (uconn *UConn) GetGREASESeed() [ssl_grease_last_index]uint16 {
	return uconn.greaseSeed
}

// MakeConnWithCompleteHandshake allows to forge both server and client side TLS connections.
// Major Hack Alert.
func MakeConnWithCompleteHandshake(tcpConn net.Conn, version uint16, cipherSuite uint16, masterSecret []byte, clientRandom []byte, serverRandom []byte, isClient bool) *Conn {
	tlsConn := &Conn{conn: tcpConn, config: &Config{}, isClient: isClient}
	cs := cipherSuiteByID(cipherSuite)
	if cs != nil {
		// This is mostly borrowed from establishKeys()
		clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
			keysFromMasterSecret(version, cs, masterSecret, clientRandom, serverRandom,
				cs.macLen, cs.keyLen, cs.ivLen)

		var clientCipher, serverCipher interface{}
		var clientHash, serverHash hash.Hash
		if cs.cipher != nil {
			clientCipher = cs.cipher(clientKey, clientIV, true /* for reading */)
			clientHash = cs.mac(clientMAC)
			serverCipher = cs.cipher(serverKey, serverIV, false /* not for reading */)
			serverHash = cs.mac(serverMAC)
		} else {
			clientCipher = cs.aead(clientKey, clientIV)
			serverCipher = cs.aead(serverKey, serverIV)
		}

		if isClient {
			tlsConn.in.prepareCipherSpec(version, serverCipher, serverHash)
			tlsConn.out.prepareCipherSpec(version, clientCipher, clientHash)
		} else {
			tlsConn.in.prepareCipherSpec(version, clientCipher, clientHash)
			tlsConn.out.prepareCipherSpec(version, serverCipher, serverHash)
		}

		// skip the handshake states
		tlsConn.isHandshakeComplete.Store(true)
		tlsConn.cipherSuite = cipherSuite
		tlsConn.haveVers = true
		tlsConn.vers = version

		// Update to the new cipher specs
		// and consume the finished messages
		tlsConn.in.changeCipherSpec()
		tlsConn.out.changeCipherSpec()

		tlsConn.in.incSeq()
		tlsConn.out.incSeq()

		return tlsConn
	} else {
		// TODO: Support TLS 1.3 Cipher Suites
		return nil
	}
}

func makeSupportedVersions(minVers, maxVers uint16) []uint16 {
	a := make([]uint16, maxVers-minVers+1)
	for i := range a {
		a[i] = maxVers - uint16(i)
	}
	return a
}

// Extending (*Conn).readHandshake() to support more customized handshake messages.
func (c *Conn) utlsHandshakeMessageType(msgType byte) (handshakeMessage, error) {
	switch msgType {
	case utlsTypeCompressedCertificate:
		return new(utlsCompressedCertificateMsg), nil
	case utlsTypeEncryptedExtensions:
		if c.isClient {
			return new(encryptedExtensionsMsg), nil
		} else {
			return new(utlsClientEncryptedExtensionsMsg), nil
		}
	default:
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}
}

// Extending (*Conn).connectionStateLocked()
func (c *Conn) utlsConnectionStateLocked(state *ConnectionState) {
	state.PeerApplicationSettings = c.utls.peerApplicationSettings
}

type utlsConnExtraFields struct {
	// Application Settings (ALPS)
	peerApplicationSettings      []byte
	localApplicationSettings     []byte
	applicationSettingsCodepoint uint16

	sessionController *sessionController
}

// Read reads data from the connection.
//
// As Read calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both Read and [Conn.Write] before Read is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *UConn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := c.input.Read(b)

	// If a close-notify alert is waiting, read it so that we can return (n,
	// EOF) instead of (n, nil), to signal to the HTTP response reading
	// goroutine that the connection is now closed. This eliminates a race
	// where the HTTP response reading goroutine would otherwise not observe
	// the EOF until its next read, by which time a client goroutine might
	// have already tried to reuse the HTTP connection for a new request.
	// See https://golang.org/cl/76400046 and https://golang.org/issue/3514
	if n != 0 && c.input.Len() == 0 && c.rawInput.Len() > 0 &&
		recordType(c.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err // will be io.EOF on closeNotify
		}
	}

	return n, nil
}

// handleRenegotiation processes a HelloRequest handshake message.
func (c *UConn) handleRenegotiation() error {
	if c.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert(alertNoRenegotiation)
	}

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	c.isHandshakeComplete.Store(false)

	// [uTLS section begins]
	if err = c.BuildHandshakeState(); err != nil {
		return err
	}
	// [uTLS section ends]
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return c.handshakeErr
}

// handlePostHandshakeMessage processes a handshake message arrived after the
// handshake is complete. Up to TLS 1.2, it indicates the start of a renegotiation.
func (c *UConn) handlePostHandshakeMessage() error {
	if c.vers != VersionTLS13 {
		return c.handleRenegotiation()
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many non-advancing records"))
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return c.handleNewSessionTicket(msg)
	case *keyUpdateMsg:
		return c.handleKeyUpdate(msg)
	}
	// The QUIC layer is supposed to treat an unexpected post-handshake CertificateRequest
	// as a QUIC-level PROTOCOL_VIOLATION error (RFC 9001, Section 4.4). Returning an
	// unexpected_message alert here doesn't provide it with enough information to distinguish
	// this condition from other unexpected messages. This is probably fine.
	c.sendAlert(alertUnexpectedMessage)
	return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
}
