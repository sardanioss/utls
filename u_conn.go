// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
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
	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG buildHandshakeState] uconn=%p, loadSession=%v, clientHelloBuildStatus=%d\n", uconn, loadSession, uconn.clientHelloBuildStatus)
	}
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
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: SessionTicketsDisabled=%v, cacheNil=%v - skipping\n",
				uconn, cfg.SessionTicketsDisabled, cfg.ClientSessionCache == nil)
		}
		return nil
	}
	shouldLoad := uconn.sessionController.shouldLoadSession()
	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: shouldLoadSession=%d\n", uconn, shouldLoad)
	}
	switch shouldLoad {
	case shouldReturn:
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: case shouldReturn\n", uconn)
		}
	case shouldSetTicket:
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: case shouldSetTicket\n", uconn)
		}
		uconn.sessionController.setSessionTicketToUConn()
	case shouldSetPsk:
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: case shouldSetPsk\n", uconn)
		}
		uconn.sessionController.setPskToUConn()
	case shouldLoad:
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: case shouldLoad\n", uconn)
		}
		hello := uconn.HandshakeState.Hello.getPrivatePtr()
		uconn.sessionController.utlsAboutToLoadSession()
		session, earlySecret, binderKey, err := uconn.loadSession(hello)
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: loadSession returned session=%v, err=%v\n",
				uconn, session != nil, err)
		}
		if session == nil || err != nil {
			return err
		}
		if session.version == VersionTLS12 {
			// We use the session ticket extension for tls 1.2 session resumption
			uconn.sessionController.initSessionTicketExt(session, hello.sessionTicket)
			uconn.sessionController.setSessionTicketToUConn()
		} else {
			if os.Getenv("UTLS_ECH_DEBUG") != "" {
				fmt.Printf("[ECH DEBUG uLoadSession] uconn=%p: initPskExt with TLS 1.3 session\n", uconn)
			}
			uconn.sessionController.initPskExt(session, earlySecret, binderKey, hello.pskIdentities)
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

	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG] === computeAndUpdateOuterECHExtension START ===\n")
		fmt.Printf("[ECH DEBUG]   useKey: %v\n", useKey)
		fmt.Printf("[ECH DEBUG]   ech.config.ConfigID: %d\n", ech.config.ConfigID)
		fmt.Printf("[ECH DEBUG]   ech.kdfID: %d, ech.aeadID: %d\n", ech.kdfID, ech.aeadID)
		fmt.Printf("[ECH DEBUG]   inner.serverName: %s\n", inner.serverName)
		fmt.Printf("[ECH DEBUG]   outer SNI in extensions: looking up...\n")
		for _, ext := range uconn.Extensions {
			if sniExt, ok := ext.(*SNIExtension); ok {
				fmt.Printf("[ECH DEBUG]   SNIExtension.ServerName: %s\n", sniExt.ServerName)
				break
			}
		}
	}

	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
	}

	encodedInner, err := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), outerExts)
	if err != nil {
		return err
	}

	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG]   encodedInner length: %d bytes\n", len(encodedInner))
		if len(encodedInner) > 32 {
			fmt.Printf("[ECH DEBUG]   encodedInner (first 32): %x\n", encodedInner[:32])
		}
	}

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

	// If PSK extension is provided, recalculate binder using bytes from serialized outer hello
	// This ensures binder is calculated over the EXACT bytes the server will see
	if pskExt != nil && pskExt.cipherSuite != nil && len(pskExt.BinderKey) > 0 {
		// Extract extension bytes from the serialized outer hello
		outerExtRawBytes := extractExtensionBytesFromHello(serializedOuter)
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG] PSK binder recalculation using serialized outer bytes:\n")
			fmt.Printf("[ECH DEBUG]   Extracted %d extensions from serialized outer\n", len(outerExtRawBytes))
		}

		// Get outer session_id - per ECH spec, server copies this to expanded inner hello
		outerSessionId := uconn.HandshakeState.Hello.SessionId

		// Calculate binder using the ACTUAL bytes from serialized outer
		helloBytes, err := inner.marshalExpandedECHWithoutBinders(outerExts, outerExtRawBytes, outerSessionId)
		if err != nil {
			return fmt.Errorf("failed to marshal inner hello for PSK binder recalculation: %w", err)
		}

		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			debugLen := len(helloBytes)
			if debugLen > 100 {
				debugLen = 100
			}
			fmt.Printf("[ECH DEBUG]   Expanded inner for binder (len=%d): %x...\n", len(helloBytes), helloBytes[:debugLen])
		}

		// Calculate binder
		transcript := pskExt.cipherSuite.hash.New()
		transcript.Write(helloBytes)
		innerBinders := [][]byte{pskExt.cipherSuite.finishedHash(pskExt.BinderKey, transcript)}

		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG]   Recalculated PSK binder: %x\n", innerBinders[0])
		}

		// Update inner hello's binders
		inner.pskBinders = innerBinders

		// Re-encode inner hello with the correct binders
		encodedInner, err = encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), outerExts)
		if err != nil {
			return fmt.Errorf("failed to re-encode inner hello after PSK binder recalculation: %w", err)
		}

		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG]   Re-encoded inner hello length: %d bytes\n", len(encodedInner))
		}

		// Store the encoded (compressed) inner hello for use in echTranscriptMsg
		// This ensures we decode the EXACT same bytes the server received
		ech.encodedInnerHello = encodedInner

		// Store the full expanded inner hello (WITH binders) for early traffic secret calculation
		// This ensures we use the EXACT same bytes as the PSK binder calculation
		fullExpandedInner, err := inner.marshalExpandedECH(outerExts, outerExtRawBytes, outerSessionId)
		if err != nil {
			return fmt.Errorf("failed to marshal full expanded inner hello: %w", err)
		}
		ech.expandedInnerHello = fullExpandedInner
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG]   Stored expanded inner hello (with binders) for early traffic: len=%d\n", len(fullExpandedInner))
		}
	}

	// Debug: print outer hello SNI
	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		// Parse the outer hello to find SNI
		fmt.Printf("[ECH DEBUG] Outer hello length: %d bytes\n", len(serializedOuter))
		// Skip: version(2) + random(32) + sessionID(var) + cipherSuites(var) + compression(var)
		if len(serializedOuter) > 38 {
			offset := 34 // version(2) + random(32)
			sessionIdLen := int(serializedOuter[offset])
			offset += 1 + sessionIdLen
			cipherSuitesLen := int(serializedOuter[offset])<<8 | int(serializedOuter[offset+1])
			offset += 2 + cipherSuitesLen
			compressionLen := int(serializedOuter[offset])
			offset += 1 + compressionLen
			if offset+2 < len(serializedOuter) {
				extensionsLen := int(serializedOuter[offset])<<8 | int(serializedOuter[offset+1])
				offset += 2
				fmt.Printf("[ECH DEBUG] Outer extensions length: %d\n", extensionsLen)
				endOffset := offset + extensionsLen
				for offset+4 <= len(serializedOuter) && offset < endOffset {
					extType := int(serializedOuter[offset])<<8 | int(serializedOuter[offset+1])
					extLen := int(serializedOuter[offset+2])<<8 | int(serializedOuter[offset+3])
					if extType == 0 { // SNI extension
						if offset+4+extLen <= len(serializedOuter) {
							// SNI format: list_len(2) + name_type(1) + name_len(2) + name
							sniListLen := int(serializedOuter[offset+4])<<8 | int(serializedOuter[offset+5])
							if sniListLen > 0 && offset+8 < len(serializedOuter) {
								sniNameLen := int(serializedOuter[offset+7])<<8 | int(serializedOuter[offset+8])
								if offset+9+sniNameLen <= len(serializedOuter) {
									sniName := string(serializedOuter[offset+9 : offset+9+sniNameLen])
									fmt.Printf("[ECH DEBUG] Outer SNI in bytes: %s\n", sniName)
								}
							}
						}
					}
					offset += 4 + extLen
				}
			}
		}
	}

	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG] === HPKE Seal Operation ===\n")
		fmt.Printf("[ECH DEBUG]   AAD (serializedOuter) length: %d bytes\n", len(serializedOuter))
		fmt.Printf("[ECH DEBUG]   Plaintext (encodedInner) length: %d bytes\n", len(encodedInner))

		// Dump FULL encodedInner (plaintext being encrypted)
		fmt.Printf("\n[ECH DEBUG] === FULL ENCODED INNER (PLAINTEXT) ===\n")
		for i := 0; i < len(encodedInner); i += 64 {
			end := i + 64
			if end > len(encodedInner) {
				end = len(encodedInner)
			}
			fmt.Printf("[INNER %04d-%04d] %x\n", i, end, encodedInner[i:end])
		}
		fmt.Printf("[ECH DEBUG] === END ENCODED INNER ===\n\n")

		if len(serializedOuter) > 32 {
			fmt.Printf("[ECH DEBUG]   AAD (first 32): %x\n", serializedOuter[:32])
		}
		// Print session_id from serialized outer (at offset 34)
		if len(serializedOuter) > 34 {
			outerSessionIdLen := int(serializedOuter[34])
			fmt.Printf("[ECH DEBUG]   Outer hello session_id len (in AAD): %d\n", outerSessionIdLen)
			if outerSessionIdLen > 0 && len(serializedOuter) > 35+outerSessionIdLen {
				fmt.Printf("[ECH DEBUG]   Outer hello session_id (in AAD): %x\n", serializedOuter[35:35+outerSessionIdLen])
			}
		}
		// Extract and print key extension bytes from serialized outer for comparison
		// This helps verify if captured raw bytes match what's actually in the outer hello
		outerExtMap := extractExtensionBytesFromHello(serializedOuter)
		fmt.Printf("[ECH DEBUG]   Extracted %d extensions from serialized outer hello\n", len(outerExtMap))
		// Print first 16 bytes of key extensions for comparison
		for _, extType := range []uint16{51, 10, 13, 45, 57, 16} { // key_share, curves, sig_algs, psk_modes, quic, alpn
			if bytes, ok := outerExtMap[extType]; ok {
				previewLen := 16
				if len(bytes) < previewLen {
					previewLen = len(bytes)
				}
				fmt.Printf("[ECH DEBUG]   Outer ext %d (0x%04x) in AAD: len=%d, first %d bytes: %x\n",
					extType, extType, len(bytes), previewLen, bytes[:previewLen])
			}
		}
	}

	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG]   HPKE Seal ERROR: %v\n", err)
		}
		return err
	}

	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG]   HPKE Seal SUCCESS, ciphertext length: %d bytes\n", len(encryptedInner))
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
	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		edIdx := -1
		for i, ext := range uconn.Extensions {
			if _, ok := ext.(*FakeEarlyDataExtension); ok {
				edIdx = i
				break
			}
		}
		fmt.Printf("[ECH DEBUG] FakeEarlyDataExtension in outer hello at idx=%d (keeping for ech_outer_extensions)\n", edIdx)
	}

	// Debug: print all outer extension types before final marshal
	// Store serializedOuter (first marshal AAD) for comparison
	firstMarshalAAD := make([]byte, len(serializedOuter))
	copy(firstMarshalAAD, serializedOuter)

	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		var outerExtTypes []uint16
		for _, ext := range uconn.Extensions {
			buffer := make([]byte, 2000)
			ext.Read(buffer)
			extType := uint16(buffer[0])<<8 | uint16(buffer[1])
			outerExtTypes = append(outerExtTypes, extType)
		}
		fmt.Printf("[ECH DEBUG] Outer extension types for final marshal: %v\n", outerExtTypes)
	}

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	if os.Getenv("UTLS_ECH_DEBUG") != "" {
		fmt.Printf("[ECH DEBUG] === computeAndUpdateOuterECHExtension DONE ===\n")
		fmt.Printf("[ECH DEBUG]   Final outer hello length: %d bytes\n", len(uconn.HandshakeState.Hello.Raw))

		// CRITICAL: Compare AAD (first marshal) with what server would compute
		// Server takes received hello (second marshal) and zeros ECH payload
		finalMarshal := uconn.HandshakeState.Hello.Raw[4:] // Skip header

		// Find ECH extension in both marshals and compare EVERYTHING
		fmt.Printf("\n[ECH DEBUG] ============ COMPREHENSIVE AAD COMPARISON ============\n")
		fmt.Printf("[ECH DEBUG] First marshal (AAD for HPKE Seal): %d bytes\n", len(firstMarshalAAD))
		fmt.Printf("[ECH DEBUG] Second marshal (sent to server):  %d bytes\n", len(finalMarshal))

		// Dump FULL first marshal AAD
		fmt.Printf("\n[ECH DEBUG] === FULL FIRST MARSHAL (AAD) ===\n")
		for i := 0; i < len(firstMarshalAAD); i += 64 {
			end := i + 64
			if end > len(firstMarshalAAD) {
				end = len(firstMarshalAAD)
			}
			fmt.Printf("[AAD %04d-%04d] %x\n", i, end, firstMarshalAAD[i:end])
		}

		// Dump FULL second marshal
		fmt.Printf("\n[ECH DEBUG] === FULL SECOND MARSHAL (SENT) ===\n")
		for i := 0; i < len(finalMarshal); i += 64 {
			end := i + 64
			if end > len(finalMarshal) {
				end = len(finalMarshal)
			}
			fmt.Printf("[SENT %04d-%04d] %x\n", i, end, finalMarshal[i:end])
		}

		// Find ECH extension in both and create "server view" (with payload zeroed)
		findECHExtension := func(data []byte) (offset, headerLen, payloadLen int, found bool) {
			if len(data) < 38 {
				return 0, 0, 0, false
			}
			off := 34 // version(2) + random(32)
			sessionIdLen := int(data[off])
			off += 1 + sessionIdLen
			if off+2 > len(data) {
				return 0, 0, 0, false
			}
			cipherSuitesLen := int(data[off])<<8 | int(data[off+1])
			off += 2 + cipherSuitesLen
			if off+1 > len(data) {
				return 0, 0, 0, false
			}
			compressionLen := int(data[off])
			off += 1 + compressionLen
			if off+2 > len(data) {
				return 0, 0, 0, false
			}
			extensionsLen := int(data[off])<<8 | int(data[off+1])
			off += 2
			endOff := off + extensionsLen
			for off+4 <= len(data) && off < endOff {
				extType := int(data[off])<<8 | int(data[off+1])
				extLen := int(data[off+2])<<8 | int(data[off+3])
				if extType == 0xfe0d { // ECH extension
					// ECH format: type(1) + kdf(2) + aead(2) + config_id(1) + enc_len(2) + enc(enc_len) + payload_len(2) + payload
					if off+4+extLen <= len(data) && extLen > 8 {
						echData := data[off+4 : off+4+extLen]
						encLen := int(echData[6])<<8 | int(echData[7])
						if 8+encLen+2 <= len(echData) {
							pLen := int(echData[8+encLen])<<8 | int(echData[8+encLen+1])
							hLen := 8 + encLen + 2 // header length (everything before payload)
							return off + 4, hLen, pLen, true
						}
					}
				}
				off += 4 + extLen
			}
			return 0, 0, 0, false
		}

		echOff1, hdrLen1, payloadLen1, found1 := findECHExtension(firstMarshalAAD)
		echOff2, hdrLen2, payloadLen2, found2 := findECHExtension(finalMarshal)

		fmt.Printf("\n[ECH DEBUG] === ECH EXTENSION LOCATIONS ===\n")
		fmt.Printf("[ECH DEBUG] First marshal:  found=%v, offset=%d, headerLen=%d, payloadLen=%d\n", found1, echOff1, hdrLen1, payloadLen1)
		fmt.Printf("[ECH DEBUG] Second marshal: found=%v, offset=%d, headerLen=%d, payloadLen=%d\n", found2, echOff2, hdrLen2, payloadLen2)

		if found1 && found2 {
			// Compare ECH headers (should be identical)
			echHeader1 := firstMarshalAAD[echOff1 : echOff1+hdrLen1]
			echHeader2 := finalMarshal[echOff2 : echOff2+hdrLen2]
			fmt.Printf("\n[ECH DEBUG] === ECH HEADER COMPARISON ===\n")
			fmt.Printf("[ECH DEBUG] First ECH header (%d bytes):  %x\n", len(echHeader1), echHeader1)
			fmt.Printf("[ECH DEBUG] Second ECH header (%d bytes): %x\n", len(echHeader2), echHeader2)

			headerMatch := len(echHeader1) == len(echHeader2)
			if headerMatch {
				for i := range echHeader1 {
					if echHeader1[i] != echHeader2[i] {
						headerMatch = false
						break
					}
				}
			}
			fmt.Printf("[ECH DEBUG] ECH headers match: %v\n", headerMatch)

			// Compare ECH payloads
			echPayload1 := firstMarshalAAD[echOff1+hdrLen1 : echOff1+hdrLen1+payloadLen1]
			echPayload2 := finalMarshal[echOff2+hdrLen2 : echOff2+hdrLen2+payloadLen2]
			fmt.Printf("\n[ECH DEBUG] === ECH PAYLOAD INFO ===\n")
			fmt.Printf("[ECH DEBUG] First ECH payload len:  %d (should be all zeros)\n", len(echPayload1))
			fmt.Printf("[ECH DEBUG] Second ECH payload len: %d (encrypted)\n", len(echPayload2))

			// Verify first payload is all zeros
			allZeros := true
			for _, b := range echPayload1 {
				if b != 0 {
					allZeros = false
					break
				}
			}
			fmt.Printf("[ECH DEBUG] First payload all zeros: %v\n", allZeros)

			// Create "server view" - second marshal with ECH payload zeroed
			serverView := make([]byte, len(finalMarshal))
			copy(serverView, finalMarshal)
			for i := 0; i < payloadLen2; i++ {
				serverView[echOff2+hdrLen2+i] = 0
			}

			// Compare firstMarshalAAD with serverView byte-by-byte
			fmt.Printf("\n[ECH DEBUG] === BYTE-BY-BYTE AAD vs SERVER VIEW COMPARISON ===\n")
			if len(firstMarshalAAD) != len(serverView) {
				fmt.Printf("[ECH DEBUG] LENGTH MISMATCH! AAD=%d, ServerView=%d\n", len(firstMarshalAAD), len(serverView))
			} else {
				differences := 0
				for i := range firstMarshalAAD {
					if firstMarshalAAD[i] != serverView[i] {
						differences++
						if differences <= 20 {
							fmt.Printf("[ECH DEBUG] DIFF at byte %d: AAD=%02x, ServerView=%02x\n", i, firstMarshalAAD[i], serverView[i])
						}
					}
				}
				if differences == 0 {
					fmt.Printf("[ECH DEBUG] AAD and ServerView are IDENTICAL!\n")
				} else {
					fmt.Printf("[ECH DEBUG] Total differences: %d bytes\n", differences)
				}
			}
		}

		fmt.Printf("[ECH DEBUG] ============ END AAD COMPARISON ============\n\n")

		// Old ext 57 comparison
		firstExt57 := extractExtensionBytesFromHello(firstMarshalAAD)
		secondExt57 := extractExtensionBytesFromHello(finalMarshal)
		if ext57First, ok1 := firstExt57[57]; ok1 {
			if ext57Second, ok2 := secondExt57[57]; ok2 {
				if len(ext57First) != len(ext57Second) {
					fmt.Printf("[ECH DEBUG] WARNING: Ext 57 LENGTH MISMATCH between marshals! first=%d, second=%d\n",
						len(ext57First), len(ext57Second))
				} else {
					match := true
					for i := range ext57First {
						if ext57First[i] != ext57Second[i] {
							match = false
							break
						}
					}
					if !match {
						fmt.Printf("[ECH DEBUG] WARNING: Ext 57 BYTES MISMATCH between marshals!\n")
						previewLen := 16
						if len(ext57First) < previewLen {
							previewLen = len(ext57First)
						}
						fmt.Printf("[ECH DEBUG]   First marshal:  %x\n", ext57First[:previewLen])
						fmt.Printf("[ECH DEBUG]   Second marshal: %x\n", ext57Second[:previewLen])
					} else {
						fmt.Printf("[ECH DEBUG]   Ext 57 matches between first and second marshal (len=%d)\n", len(ext57First))
					}
				}
			}
		}

		// Find and print the ECH extension bytes
		raw := uconn.HandshakeState.Hello.Raw
		if len(raw) > 4 {
			offset := 4 + 34 // header + version + random
			if offset < len(raw) {
				sessionIdLen := int(raw[offset])
				offset += 1 + sessionIdLen
				if offset+2 < len(raw) {
					cipherSuitesLen := int(raw[offset])<<8 | int(raw[offset+1])
					offset += 2 + cipherSuitesLen
					if offset+1 < len(raw) {
						compressionLen := int(raw[offset])
						offset += 1 + compressionLen
						if offset+2 < len(raw) {
							extLen := int(raw[offset])<<8 | int(raw[offset+1])
							offset += 2
							endOffset := offset + extLen
							for offset+4 <= len(raw) && offset < endOffset {
								extType := int(raw[offset])<<8 | int(raw[offset+1])
								extDataLen := int(raw[offset+2])<<8 | int(raw[offset+3])
								if extType == 0xfe0d { // ECH extension
									fmt.Printf("[ECH DEBUG]   ECH extension at offset %d, len=%d\n", offset, extDataLen)
									if offset+4+extDataLen <= len(raw) && extDataLen > 10 {
										echData := raw[offset+4 : offset+4+extDataLen]
										fmt.Printf("[ECH DEBUG]   ECH ext: type=%d kdf=%d aead=%d configId=%d encapKeyLen=%d\n",
											echData[0],
											int(echData[1])<<8|int(echData[2]),
											int(echData[3])<<8|int(echData[4]),
											echData[5],
											int(echData[6])<<8|int(echData[7]))
										encapKeyLen := int(echData[6])<<8 | int(echData[7])
										if 8+encapKeyLen+2 <= len(echData) {
											payloadLen := int(echData[8+encapKeyLen])<<8 | int(echData[8+encapKeyLen+1])
											fmt.Printf("[ECH DEBUG]   ECH ext: encapKey (first 8)=%x, payloadLen=%d\n",
												echData[8:8+8], payloadLen)
										}
									}
									break
								}
								offset += 4 + extDataLen
							}
						}
					}
				}
			}
		}
	}

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
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("\n[ECH DEBUG] ========== MarshalClientHello START ==========\n")
			fmt.Printf("[ECH DEBUG] ECHConfigList length: %d bytes\n", len(uconn.config.EncryptedClientHelloConfigList))
			fmt.Printf("[ECH DEBUG] ServerName: %s\n", uconn.config.ServerName)

			// Check if PSK extension is present
			for _, ext := range uconn.Extensions {
				if psk, ok := ext.(*UtlsPreSharedKeyExtension); ok {
					fmt.Printf("[ECH DEBUG] PSK extension present: identities=%d, binderKey=%d bytes\n",
						len(psk.Identities), len(psk.BinderKey))
					break
				}
			}
		}

		inner, _, ech, err := uconn.makeClientHello()
		if err != nil {
			return err
		}

		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG] After makeClientHello:\n")
			fmt.Printf("[ECH DEBUG]   ech.config.ConfigID: %d\n", ech.config.ConfigID)
			fmt.Printf("[ECH DEBUG]   ech.config.PublicName: %s\n", string(ech.config.PublicName))
			fmt.Printf("[ECH DEBUG]   ech.config.KemID: %d\n", ech.config.KemID)
			fmt.Printf("[ECH DEBUG]   ech.kdfID: %d, ech.aeadID: %d\n", ech.kdfID, ech.aeadID)
			fmt.Printf("[ECH DEBUG]   ech.encapsulatedKey len: %d\n", len(ech.encapsulatedKey))
			if len(ech.encapsulatedKey) > 8 {
				fmt.Printf("[ECH DEBUG]   ech.encapsulatedKey (first 8): %x\n", ech.encapsulatedKey[:8])
			}
			fmt.Printf("[ECH DEBUG]   inner.serverName: %s\n", inner.serverName)
			fmt.Printf("[ECH DEBUG]   inner.random (first 8): %x\n", inner.random[:8])
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

		// Per ECH spec: early_data MUST be in inner hello only, NOT in outer hello
		// The inner already has earlyData copied above, now clear it from outer
		// This prevents the outer ClientHello from including the early_data extension
		uconn.HandshakeState.Hello.EarlyData = false

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

		// For ECH + PSK:
		// 1. The REAL PSK goes in the inner ClientHello with binders calculated over inner transcript
		// 2. The outer ClientHello must have a GREASE PSK (random data, same length) per ECH spec
		// See: draft-ietf-tls-esni Section 6.1.3 - "clients SHOULD send a GREASE pre_shared_key extension"
		var pskExtIdx int = -1
		// Save the outer extensions list BEFORE any PSK replacement, so we can use the correct
		// extension types (with real PSK type 41) for encoding the inner hello
		var outerExtsList []uint16
		if pskExt != nil && pskExt.cipherSuite != nil && len(pskExt.BinderKey) > 0 && len(pskExt.Identities) > 0 {
			// Find the PSK extension index for later GREASE replacement
			for i, ext := range uconn.Extensions {
				if _, ok := ext.(*UtlsPreSharedKeyExtension); ok {
					pskExtIdx = i
					break
				}
			}

			if os.Getenv("UTLS_ECH_DEBUG") != "" {
				fmt.Printf("[ECH DEBUG] PSK extension from outer: identities=%d, binders=%d\n", len(pskExt.Identities), len(pskExt.Binders))
				for i, id := range pskExt.Identities {
					fmt.Printf("[ECH DEBUG]   outer identity[%d]: label_len=%d, ticket_age=0x%08x\n", i, len(id.Label), id.ObfuscatedTicketAge)
				}
			}

			// Copy PSK identities from the extension to inner hello
			inner.pskIdentities = PskIdentities(pskExt.Identities).ToPrivate()

			// Create placeholder binders of correct size
			inner.pskBinders = make([][]byte, len(inner.pskIdentities))
			for i := range inner.pskIdentities {
				inner.pskBinders[i] = make([]byte, pskExt.cipherSuite.hash.Size())
			}

			// Marshal inner hello using EXPANDED format without binders to create transcript
			// The server expands ech_outer_extensions and verifies the binder over that format
			// We must use the same extension order as the outer hello
			outerExtsList = uconn.extensionsList()
			// Chrome reference: early_data (42) IS included in both outer hello AND ech_outer_extensions for PSK
			// The inner hello references early_data via ech_outer_extensions (not inline)

			// NOTE: PSK binder calculation is now done INSIDE computeAndUpdateOuterECHExtensionWithOuterExts
			// AFTER the outer hello is serialized, using bytes extracted from the serialized outer.
			// This ensures the binder is calculated over the EXACT bytes the server will see.

			// Now create GREASE PSK for the outer hello
			// GREASE PSK has random identities and binders of the same length as the real ones
			if pskExtIdx >= 0 {
				greasePskExt := &UtlsPreSharedKeyExtension{
					PreSharedKeyCommon: PreSharedKeyCommon{
						Identities: make([]PskIdentity, len(pskExt.Identities)),
						Binders:    make([][]byte, len(pskExt.Binders)),
					},
				}

				// Generate random PSK identities with same length
				for i, realIdentity := range pskExt.Identities {
					greasePskExt.Identities[i] = PskIdentity{
						Label: make([]byte, len(realIdentity.Label)),
					}
					// Fill identity with random bytes
					if _, err := io.ReadFull(rand.Reader, greasePskExt.Identities[i].Label); err != nil {
						return fmt.Errorf("failed to generate GREASE PSK identity: %w", err)
					}
					// Generate random obfuscated ticket age
					var ticketAge [4]byte
					if _, err := io.ReadFull(rand.Reader, ticketAge[:]); err != nil {
						return fmt.Errorf("failed to generate GREASE ticket age: %w", err)
					}
					greasePskExt.Identities[i].ObfuscatedTicketAge = uint32(ticketAge[0])<<24 | uint32(ticketAge[1])<<16 | uint32(ticketAge[2])<<8 | uint32(ticketAge[3])
				}

				// Generate random binders with same length
				for i, realBinder := range pskExt.Binders {
					greasePskExt.Binders[i] = make([]byte, len(realBinder))
					if _, err := io.ReadFull(rand.Reader, greasePskExt.Binders[i]); err != nil {
						return fmt.Errorf("failed to generate GREASE PSK binder: %w", err)
					}
				}

				if os.Getenv("UTLS_ECH_DEBUG") != "" {
					fmt.Printf("[ECH DEBUG] Replacing outer PSK with GREASE PSK (identities=%d, binders=%d)\n",
						len(greasePskExt.Identities), len(greasePskExt.Binders))
				}

				// Replace the real PSK extension with GREASE in the extensions list
				uconn.Extensions[pskExtIdx] = greasePskExt
			}
		}

		ech.innerHello = inner

		// Debug: verify PSK is in inner hello after assignment
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG] After ech.innerHello = inner:\n")
			fmt.Printf("[ECH DEBUG]   inner.pskIdentities len: %d\n", len(inner.pskIdentities))
			fmt.Printf("[ECH DEBUG]   ech.innerHello.pskIdentities len: %d\n", len(ech.innerHello.pskIdentities))
			fmt.Printf("[ECH DEBUG]   inner ptr: %p, ech.innerHello ptr: %p\n", inner, ech.innerHello)
			fmt.Printf("[ECH DEBUG]   uconn ptr: %p, clientHelloBuildStatus: %d\n", uconn, uconn.clientHelloBuildStatus)
		}

		// Debug: compare inner and outer random values
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG] Inner random: %x\n", inner.random[:8])
			fmt.Printf("[ECH DEBUG] Outer random: %x\n", uconn.HandshakeState.Hello.Random[:8])
		}

		// For ECH, the outer hello's SNI must be the ECH public name (from ECH config)
		// Save the original SNI to restore after ECH computation if needed
		originalServerName := uconn.config.ServerName
		publicName := string(ech.config.PublicName)

		// Debug: print SNI change
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG] Updating outer SNI: %s -> %s\n", originalServerName, publicName)
		}

		// Update outer SNI extension to use the ECH public name
		uconn.config.ServerName = publicName
		sniFound := false
		for _, ext := range uconn.Extensions {
			if sniExt, ok := ext.(*SNIExtension); ok {
				sniExt.ServerName = publicName
				sniFound = true
				if os.Getenv("UTLS_ECH_DEBUG") != "" {
					fmt.Printf("[ECH DEBUG] Updated SNIExtension.ServerName to: %s\n", sniExt.ServerName)
				}
				break
			}
		}
		if os.Getenv("UTLS_ECH_DEBUG") != "" && !sniFound {
			fmt.Printf("[ECH DEBUG] WARNING: No SNIExtension found in Extensions!\n")
		}

		// Use the saved outerExtsList if available (computed before GREASE PSK replacement)
		// This ensures we encode the inner hello with the correct PSK extension type (41)
		// instead of the GREASE PSK which has type 0 when reading from buffer
		var echErr error
		if outerExtsList != nil {
			if os.Getenv("UTLS_ECH_DEBUG") != "" {
				fmt.Printf("[ECH DEBUG] Using outerExtsList for compressed inner: %v\n", outerExtsList)
			}
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
		if os.Getenv("UTLS_ECH_DEBUG") != "" {
			fmt.Printf("[ECH DEBUG] Setting uconn.echCtx: uconn=%p, ech=%p, ech.innerHello=%p, pskIdentities=%d\n",
				uconn, ech, ech.innerHello, len(ech.innerHello.pskIdentities))
		}
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
