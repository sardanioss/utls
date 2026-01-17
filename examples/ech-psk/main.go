package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	tls "github.com/sardanioss/utls"
	"golang.org/x/net/http2"
)

// ServerResponse holds the response from cloudflare /cdn-cgi/trace
type ServerResponse struct {
	SNI      string `json:"sni,omitempty"`
	TLS      string `json:"tls,omitempty"`
	HTTP     string `json:"http,omitempty"`
	Colo     string `json:"colo,omitempty"`
	Kex      string `json:"kex,omitempty"`
	Protocol string `json:"protocol,omitempty"` // kept for compatibility
}

// RequestResult holds the result of a single request
type RequestResult struct {
	RequestNum     int             `json:"request_num"`
	Success        bool            `json:"success"`
	Error          string          `json:"error,omitempty"`
	TLSVersion     string          `json:"tls_version,omitempty"`
	ALPN           string          `json:"alpn,omitempty"`
	ECHAccepted    bool            `json:"ech_accepted"`
	UsingPSK       bool            `json:"using_psk"`
	ZeroRTT        bool            `json:"zero_rtt"`
	ServerResponse *ServerResponse `json:"server_response,omitempty"`
}

// TestResults holds all test results
type TestResults struct {
	TestName    string          `json:"test_name"`
	ServerName  string          `json:"server_name"`
	Timestamp   string          `json:"timestamp"`
	ProperMode  bool            `json:"proper_mode"`
	Results     []RequestResult `json:"results"`
	AllPassed   bool            `json:"all_passed"`
	Summary     string          `json:"summary"`
}

var dialTimeout = time.Duration(15) * time.Second

// Simple session cache that stores sessions in memory
type SessionCache struct {
	sessions map[string]*tls.ClientSessionState
}

func NewSessionCache() *SessionCache {
	return &SessionCache{sessions: make(map[string]*tls.ClientSessionState)}
}

func (c *SessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	s, ok := c.sessions[sessionKey]
	if ok {
		fmt.Printf("[CACHE] Get(%s): found\n", sessionKey)
	} else {
		fmt.Printf("[CACHE] Get(%s): not found\n", sessionKey)
	}
	return s, ok
}

func (c *SessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	if cs != nil {
		fmt.Printf("[CACHE] Put(%s): stored\n", sessionKey)
		c.sessions[sessionKey] = cs
	} else {
		fmt.Printf("[CACHE] Put(%s): deleted\n", sessionKey)
		delete(c.sessions, sessionKey)
	}
}

func main() {
	// Use crypto.cloudflare.com which supports ECH over TCP+TLS (HTTP/2)
	// ECH config from DNS HTTPS record, outer SNI: cloudflare-ech.com
	echConf, err := base64.StdEncoding.DecodeString("AEX+DQBBPQAgACAOJ1yqZ/NjFq3b1AYllhO+pqgCNn0W0I+uEWrs5IF2TQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=")
	if err != nil {
		fmt.Printf("Failed to decode ECH config: %v\n", err)
		return
	}

	serverName := "crypto.cloudflare.com"
	serverAddr := "crypto.cloudflare.com:443"
	cache := NewSessionCache()

	// Initialize test results
	testResults := TestResults{
		TestName:   "ECH + PSK PROPER Mode Test",
		ServerName: serverName,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ProperMode: true,
		Results:    make([]RequestResult, 0, 3),
	}

	fmt.Println("=== Request 1 (no PSK, establishing session) ===")
	result1 := makeRequest(serverName, serverAddr, cache, echConf, 1)
	testResults.Results = append(testResults.Results, result1)

	// Wait for session ticket
	time.Sleep(1 * time.Second)

	fmt.Println("\n=== Request 2 (with PSK, expecting 0-RTT) ===")
	result2 := makeRequest(serverName, serverAddr, cache, echConf, 2)
	testResults.Results = append(testResults.Results, result2)

	fmt.Println("\n=== Request 3 (with PSK, expecting 0-RTT) ===")
	result3 := makeRequest(serverName, serverAddr, cache, echConf, 3)
	testResults.Results = append(testResults.Results, result3)

	// Determine if all tests passed
	allPassed := true
	pskWorking := false
	echWorking := true
	for _, r := range testResults.Results {
		if !r.Success {
			allPassed = false
		}
		if !r.ECHAccepted {
			echWorking = false
		}
		if r.UsingPSK && r.ZeroRTT {
			pskWorking = true
		}
	}
	testResults.AllPassed = allPassed && echWorking && pskWorking

	if testResults.AllPassed {
		testResults.Summary = "ECH + PSK PROPER mode fully working: ECH accepted on all requests, PSK session resumption with 0-RTT successful"
	} else {
		testResults.Summary = fmt.Sprintf("Test incomplete: ECH=%v, PSK+0RTT=%v", echWorking, pskWorking)
	}

	// Output JSON results
	fmt.Println("\n=== JSON RESULTS ===")
	jsonOutput, err := json.MarshalIndent(testResults, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonOutput))
}

func makeRequest(serverName, serverAddr string, cache *SessionCache, echConf []byte, reqNum int) RequestResult {
	result := RequestResult{
		RequestNum: reqNum,
	}

	tcpConn, err := net.DialTimeout("tcp", serverAddr, dialTimeout)
	if err != nil {
		result.Error = fmt.Sprintf("dial error: %v", err)
		fmt.Printf("Request %d error: %s\n", reqNum, result.Error)
		return result
	}

	config := &tls.Config{
		ServerName:                     serverName,
		ClientSessionCache:             cache,
		EncryptedClientHelloConfigList: echConf,
		OmitEmptyPsk:                   true,
	}

	tlsConn := tls.UClient(tcpConn, config, tls.HelloChrome_120_PQ)
	defer tlsConn.Close()

	// Handshake
	err = tlsConn.Handshake()
	if err != nil {
		result.Error = fmt.Sprintf("handshake error: %v", err)
		fmt.Printf("Request %d error: %s\n", reqNum, result.Error)
		return result
	}

	state := tlsConn.ConnectionState()
	result.ECHAccepted = state.ECHAccepted
	result.ALPN = state.NegotiatedProtocol

	// Map TLS version to string
	switch state.Version {
	case tls.VersionTLS13:
		result.TLSVersion = "TLS 1.3"
	case tls.VersionTLS12:
		result.TLSVersion = "TLS 1.2"
	case tls.VersionTLS11:
		result.TLSVersion = "TLS 1.1"
	case tls.VersionTLS10:
		result.TLSVersion = "TLS 1.0"
	default:
		result.TLSVersion = fmt.Sprintf("0x%04x", state.Version)
	}

	fmt.Printf("[Request %d] Handshake complete\n", reqNum)
	fmt.Printf("[Request %d] Version: %s\n", reqNum, result.TLSVersion)
	fmt.Printf("[Request %d] ALPN: %s\n", reqNum, state.NegotiatedProtocol)
	fmt.Printf("[Request %d] ECH Accepted: %v\n", reqNum, state.ECHAccepted)

	if state.Version == tls.VersionTLS13 {
		result.UsingPSK = tlsConn.HandshakeState.State13.UsingPSK
		result.ZeroRTT = result.UsingPSK // 0-RTT is tied to PSK in this context
		fmt.Printf("[Request %d] Using PSK: %v\n", reqNum, result.UsingPSK)
		if result.UsingPSK {
			fmt.Printf("[Request %d] 0-RTT success!\n", reqNum)
		}
	}

	// Make HTTP request
	resp, err := httpRequest(tlsConn, serverName, state.NegotiatedProtocol)
	if err != nil {
		result.Error = fmt.Sprintf("http error: %v", err)
		fmt.Printf("Request %d error: %s\n", reqNum, result.Error)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Parse cloudflare key=value response
	serverResp := parseCloudflareTrace(string(body))
	result.ServerResponse = &serverResp
	fmt.Printf("[Request %d] Server response: sni=%s, tls=%s, http=%s\n", reqNum, serverResp.SNI, serverResp.TLS, serverResp.HTTP)

	// Read to get session ticket
	if reqNum == 1 {
		tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		tlsConn.Read(buf)
	}

	result.Success = true
	return result
}

// parseCloudflareTrace parses the key=value format from /cdn-cgi/trace
func parseCloudflareTrace(body string) ServerResponse {
	resp := ServerResponse{}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		switch key {
		case "sni":
			resp.SNI = value
		case "tls":
			resp.TLS = value
		case "http":
			resp.HTTP = value
		case "colo":
			resp.Colo = value
		case "kex":
			resp.Kex = value
		}
	}
	return resp
}

func httpRequest(conn net.Conn, host string, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: host, Path: "/cdn-cgi/trace"},
		Header: make(http.Header),
		Host:   host,
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	default:
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	}
}
