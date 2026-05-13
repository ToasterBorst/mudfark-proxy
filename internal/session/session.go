package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mudlark-app/mudlark-proxy/internal/buffer"
	"github.com/mudlark-app/mudlark-proxy/internal/config"
)

var (
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionConflict  = errors.New("session belongs to different user")
	ErrInvalidSessionID = errors.New("invalid session ID")
	ErrMUDNotConnected  = errors.New("not connected to MUD")
)

// isExpectedDisconnectError returns true for errors that indicate a normal/expected disconnect
func isExpectedDisconnectError(err error) bool {
	if err == nil {
		return false
	}

	// EOF means the remote end closed the connection gracefully
	if errors.Is(err, io.EOF) {
		return true
	}

	// Check for common network errors that indicate disconnect
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		// Check for syscall errors
		var syscallErr syscall.Errno
		if errors.As(netErr.Err, &syscallErr) {
			switch syscallErr {
			case syscall.ECONNRESET: // Connection reset by peer
				return true
			case syscall.ECONNABORTED: // Software caused connection abort
				return true
			case syscall.EPIPE: // Broken pipe
				return true
			case syscall.ENOTCONN: // Transport endpoint is not connected
				return true
			}
		}

		// Check if underlying error message indicates closed connection
		if netErr.Err != nil {
			errMsg := netErr.Err.Error()
			if strings.Contains(errMsg, "use of closed network connection") {
				return true
			}
		}
	}

	// Check error message as fallback
	errMsg := err.Error()
	expectedMessages := []string{
		"use of closed network connection",
		"connection reset by peer",
		"broken pipe",
		"connection abort",
	}
	for _, msg := range expectedMessages {
		if strings.Contains(strings.ToLower(errMsg), msg) {
			return true
		}
	}

	return false
}

// Session represents a persistent MUD connection session
type Session struct {
	mu             sync.RWMutex
	id             string
	userID         string
	mudHost        string
	mudPort        int
	mudTLS         bool
	connectionTime int
	mudIdleTimeout time.Duration // How long to keep MUD connection alive without clients
	bufferTimeout  time.Duration // How long to keep buffer/session data
	config         *config.MUDConfig

	// MUD connection
	mudConn        net.Conn
	mudConnected   bool
	mudConnectedAt time.Time

	// Ring buffer
	buffer *buffer.RingBuffer

	// Sensitive mode (for password detection)
	sensitiveUntil time.Time
	sensitiveRE    *regexp.Regexp

	// Telnet negotiation state
	telnetParser *TelnetParser
	ttypeIndex   int // cycles through terminal types on successive TTYPE SEND requests
	nawsEnabled  bool
	gmcpEnabled  bool // true once Core.Hello has been sent to the MUD on this connection
	windowWidth  int
	windowHeight int

	// Stream reassembly (for data split across TCP packets)
	utf8Buffer *UTF8Buffer
	ansiParser *ANSIParser

	// Client broadcast
	clients   map[*Client]bool
	clientsMu sync.RWMutex

	// Lifecycle
	ctx                context.Context
	cancel             context.CancelFunc
	lastActivity       time.Time
	lastClientActivity time.Time // Last time a client was connected
	createdAt          time.Time // When the session was created
}

// Client represents a connected WebSocket client
type Client struct {
	ID       string
	SendChan chan []byte
}

// NewSession creates a new session
func NewSession(id, userID, mudHost string, mudPort, connectionTime int, mudIdleTimeoutMinutes, bufferTimeoutMinutes int, mudTLS bool, cfg *config.Config) (*Session, error) {
	if id == "" || userID == "" {
		return nil, ErrInvalidSessionID
	}

	ctx, cancel := context.WithCancel(context.Background())

	sensitiveRE, err := regexp.Compile(cfg.Buffer.SensitiveRE)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("compiling sensitive regex: %w", err)
	}

	// Determine MUD idle timeout (client specified or server default)
	mudIdleTimeout := cfg.MUD.IdleTimeout
	if mudIdleTimeoutMinutes > 0 {
		mudIdleTimeout = time.Duration(mudIdleTimeoutMinutes) * time.Minute
	}

	// Determine buffer timeout (client specified or server default of 24 hours)
	bufferTimeout := 24 * time.Hour
	if bufferTimeoutMinutes > 0 {
		bufferTimeout = time.Duration(bufferTimeoutMinutes) * time.Minute
	}

	s := &Session{
		id:                 id,
		userID:             userID,
		mudHost:            mudHost,
		mudPort:            mudPort,
		mudTLS:             mudTLS,
		connectionTime:     connectionTime,
		mudIdleTimeout:     mudIdleTimeout,
		bufferTimeout:      bufferTimeout,
		config:             &cfg.MUD,
		buffer:             buffer.NewRingBuffer(cfg.Buffer.Capacity),
		sensitiveRE:        sensitiveRE,
		windowWidth:        80,
		windowHeight:       24,
		clients:            make(map[*Client]bool),
		ctx:                ctx,
		cancel:             cancel,
		lastActivity:       time.Now(),
		lastClientActivity: time.Now(),
		createdAt:          time.Now(),
	}
	s.telnetParser = NewTelnetParser(s)
	s.utf8Buffer = NewUTF8Buffer()
	s.ansiParser = NewANSIParser()

	return s, nil
}

// ID returns the session ID
func (s *Session) ID() string {
	return s.id
}

// UserID returns the user ID that owns this session
func (s *Session) UserID() string {
	return s.userID
}

// VerifyOwnership checks if the given userID owns this session
func (s *Session) VerifyOwnership(userID string) error {
	if s.userID != userID {
		return ErrSessionConflict
	}
	return nil
}

// ConnectToMUD establishes a TCP connection to the MUD server
func (s *Session) ConnectToMUD() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mudConnected {
		return nil // Already connected
	}

	address := fmt.Sprintf("%s:%d", s.mudHost, s.mudPort)
	log.Printf("[Session %s] Connecting to MUD at %s", s.id, address)

	dialer := &net.Dialer{
		Timeout: s.config.ConnectTimeout,
	}

	conn, err := dialer.DialContext(s.ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connecting to MUD: %w", err)
	}

	// Set TCP_NODELAY to disable Nagle's algorithm (must be done on raw TCPConn before TLS wrapping)
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	var finalConn net.Conn = conn
	if s.mudTLS {
		tlsCfg := &tls.Config{
			ServerName:         s.mudHost,
			InsecureSkipVerify: false, //nolint:gosec // MUD servers commonly use self-signed certs
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(s.ctx); err != nil {
			conn.Close()
			return fmt.Errorf("TLS handshake with MUD: %w", err)
		}
		log.Printf("[Session %s] TLS handshake complete (cipher: %s)", s.id, tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
		finalConn = tlsConn
	}

	s.mudConn = finalConn
	s.mudConnected = true
	s.mudConnectedAt = time.Now()
	s.telnetParser.Reset() // fresh connection = fresh parser state
	s.gmcpEnabled = false  // reset so Core.Hello is re-sent on the new TCP connection
	s.utf8Buffer.Reset()
	s.ansiParser.Reset()

	log.Printf("[Session %s] Connected to MUD", s.id)

	// Start reading from MUD
	go s.readFromMUD()

	return nil
}

// DisconnectFromMUD closes the MUD connection
func (s *Session) DisconnectFromMUD() {
	s.mu.Lock()
	wasConnected := s.mudConnected
	if s.mudConn != nil {
		log.Printf("[Session %s] Closing MUD connection...", s.id)
		s.mudConn.Close()
		s.mudConn = nil
	}
	s.mudConnected = false
	s.mu.Unlock()

	if wasConnected {
		log.Printf("[Session %s] Disconnected from MUD", s.id)
		// Broadcast status update to all connected clients
		s.BroadcastStatus()
	}
}

// SendToMUD sends text to the MUD server
func (s *Session) SendToMUD(text string) error {
	s.mu.RLock()
	conn := s.mudConn
	connected := s.mudConnected
	s.mu.RUnlock()

	if !connected || conn == nil {
		log.Printf("[Session %s] Cannot send to MUD: not connected", s.id)
		return ErrMUDNotConnected
	}

	// Append line ending
	message := text + s.config.LineEnding

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))

	_, err := conn.Write([]byte(message))
	if err != nil {
		// Classify the error for better logging
		if isExpectedDisconnectError(err) {
			log.Printf("[Session %s] MUD connection closed while sending: %v", s.id, err)
		} else {
			log.Printf("[Session %s] Error writing to MUD: %v (type: %T)", s.id, err, err)
		}
		s.DisconnectFromMUD()
		return err
	}

	s.updateActivity()
	return nil
}

// readFromMUD reads data from the MUD connection and broadcasts to clients
func (s *Session) readFromMUD() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Session %s] MUD read loop panic recovered: %v", s.id, r)
		}
		s.DisconnectFromMUD()
	}()

	log.Printf("[Session %s] Starting MUD read loop", s.id)

	// Announce capabilities proactively. Some MUDs expect the client to send
	// WILL GMCP / WILL MSDP instead of waiting for the server to advertise.
	// optWillSent is marked here so any confirming DO from the server is
	// silently accepted without triggering a second WILL reply.
	s.sendProactiveNegotiations()

	buf := make([]byte, 4096)

	for {
		// Check if context is cancelled (graceful shutdown)
		select {
		case <-s.ctx.Done():
			log.Printf("[Session %s] MUD read loop stopping: context cancelled", s.id)
			return
		default:
		}

		s.mu.RLock()
		conn := s.mudConn
		connected := s.mudConnected
		s.mu.RUnlock()

		if conn == nil || !connected {
			log.Printf("[Session %s] MUD read loop stopping: connection closed (conn=%v, connected=%v)", s.id, conn != nil, connected)
			return
		}

		conn.SetReadDeadline(time.Time{}) // No read deadline - connection stays open until MUD closes it

		n, err := conn.Read(buf)
		if err != nil {
			// Check if this is an expected disconnect (not an error we need to worry about)
			if isExpectedDisconnectError(err) {
				log.Printf("[Session %s] MUD connection closed: %v", s.id, err)
			} else if errors.Is(err, context.Canceled) {
				log.Printf("[Session %s] MUD read cancelled (session closing)", s.id)
			} else {
				// Unexpected error - log with more detail
				log.Printf("[Session %s] Unexpected error reading from MUD: %v (type: %T)", s.id, err, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		// Pipeline: raw TCP → telnet IAC stripping → UTF-8 reassembly → ANSI sequence reassembly
		cleaned := s.telnetParser.Process(buf[:n])
		if len(cleaned) > 0 {
			complete := s.utf8Buffer.Process(cleaned)
			safe := s.ansiParser.Process(complete)
			if len(safe) > 0 {
				s.processChunk(string(safe))
			}
		}
	}
}

// sendTTYPEResponse is a no-op. This proxy never identifies its terminal type.
func (s *Session) sendTTYPEResponse() {
}

// handleCharsetRequest is a no-op. This proxy never negotiates charset.
func (s *Session) handleCharsetRequest(sbData []byte) {
}

// handleGMCP is a no-op. This proxy never processes GMCP.
func (s *Session) handleGMCP(payload []byte) {
}

// sendGMCPCoreHello sends Core.Hello and Core.Supports.Set to the MUD as soon
// as GMCP is negotiated. Many MUDs (including those that send IAC DO GMCP
// instead of the spec-correct IAC WILL GMCP) will not transmit any GMCP data
// until they receive Core.Hello.
//
// The method is guarded by gmcpEnabled so it fires at most once per TCP
// connection, even if the server sends both IAC WILL GMCP and IAC DO GMCP.
// sendGMCPCoreHello is a no-op. This proxy never sends GMCP.
func (s *Session) sendGMCPCoreHello() {
}

// sendGMCPCoreSupports sends Core.Supports.Set to the MUD.
// Called both on initial GMCP negotiation (via sendGMCPCoreHello) and whenever
// the MUD sends its own Core.Hello — some servers send Core.Hello late and
// discard any Core.Supports.Set that arrived before it.
// sendGMCPCoreSupports is a no-op. This proxy never sends GMCP.
func (s *Session) sendGMCPCoreSupports() {
}

// sendProactiveNegotiations announces GMCP and MSDP support immediately when
// the MUD connection is established, before the server has sent any option
// negotiation. This handles servers that expect the client to initiate rather
// than advertising WILL themselves.
//
// We mark optWillSent for both options before entering the read loop so that
// any confirming IAC DO reply from the server is silently accepted and does
// not trigger a second WILL reply (preventing WILL→DO→WILL→DO loops).
//
// Must be called from the readFromMUD goroutine (single-threaded access to
// telnetParser.optWillSent, no lock required).
// sendProactiveNegotiations is a no-op. This proxy never advertises capabilities.
func (s *Session) sendProactiveNegotiations() {
}

// broadcastGMCP sends a GMCP message to all connected clients.
// GMCP data is not buffered in the ring buffer — clients that are offline
// will miss real-time GMCP events (vitals, room info, etc.), which the MUD
// will re-send when the player is next active.
func (s *Session) broadcastGMCP(pkg string, data json.RawMessage) {
	message := map[string]interface{}{
		"type":    "gmcp",
		"package": pkg,
		"data":    data,
	}

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for client := range s.clients {
		select {
		case client.SendChan <- mustMarshalJSON(message):
		default:
			// Client's send buffer is full, skip
		}
	}
}

// handleMSDP processes an incoming MSDP subnegotiation from the MUD.
// Each MSDP variable update is forwarded to all connected clients as a GMCP
// message with the package name "MSDP.<VARIABLE_NAME>".  This allows the iOS
// client to handle MSDP data through its existing GMCP pipeline without any
// client-side changes.
//
// Special case: a REPORTABLE_VARIABLES update triggers automatic REPORT
// subscription for every variable the MUD lists, so the proxy self-manages
// the MSDP subscription lifecycle server-side.
// handleMSDP is a no-op. This proxy never processes MSDP.
func (s *Session) handleMSDP(payload []byte) {
}

// requestMSDPReportableVariables asks the MUD which MSDP variables it supports
// reporting. The response (a REPORTABLE_VARIABLES update) is handled by
// handleMSDP, which then sends individual REPORT commands for each variable.
// requestMSDPReportableVariables is a no-op. This proxy never requests MSDP variables.
func (s *Session) requestMSDPReportableVariables() {
}

// sendMSDPReport sends an MSDP REPORT command to start receiving updates for
// the named variable.
// sendMSDPReport is a no-op. This proxy never sends MSDP.
func (s *Session) sendMSDPReport(varName string) {
}

// sendMSDPCommand is a no-op. This proxy never sends MSDP.
func (s *Session) sendMSDPCommand(cmdVar, cmdVal string) {
}

// SendGMCPToMUD is a no-op. This proxy never sends GMCP to the MUD.
func (s *Session) SendGMCPToMUD(pkg string, data json.RawMessage) error {
	return nil
}

// sendNAWS is a no-op. This proxy never sends window size to the MUD.
func (s *Session) sendNAWS() {
}

// UpdateWindowSize updates the stored window size and sends a NAWS update if negotiated.
func (s *Session) UpdateWindowSize(width, height int) {
	if width <= 0 || height <= 0 {
		return
	}
	s.mu.Lock()
	s.windowWidth = width
	s.windowHeight = height
	nawsOn := s.nawsEnabled
	s.mu.Unlock()

	if nawsOn {
		s.sendNAWS()
	}
}

// sendTelnetResponse sends a telnet IAC response to the MUD
func (s *Session) sendTelnetResponse(response []byte) {
	s.mu.RLock()
	conn := s.mudConn
	connected := s.mudConnected
	s.mu.RUnlock()

	if !connected || conn == nil {
		log.Printf("[Session %s] Cannot send telnet response: connection closed", s.id)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(response)
	if err != nil {
		// Only log unexpected errors (not connection closed/abort errors)
		if !isExpectedDisconnectError(err) {
			log.Printf("[Session %s] Error sending telnet response: %v", s.id, err)
		}
	}
}

// processChunk handles a chunk of data from the MUD
func (s *Session) processChunk(text string) {
	// Check for password prompt
	if s.sensitiveRE.MatchString(text) {
		s.mu.Lock()
		s.sensitiveUntil = time.Now().Add(10 * time.Second)
		s.mu.Unlock()
		log.Printf("[Session %s] Entering sensitive mode", s.id)
	}

	// Check if we should buffer this chunk
	s.mu.Lock()
	inSensitiveMode := time.Now().Before(s.sensitiveUntil)
	s.mu.Unlock()

	var line buffer.Line
	if !inSensitiveMode {
		line = s.buffer.Append(text)
	} else {
		// In sensitive mode, still assign a lineID but don't buffer
		line = buffer.Line{
			LineID:    s.buffer.GetCurrentLineID() + 1,
			Text:      text,
			Timestamp: time.Now().Unix(),
		}
	}

	// Broadcast to all connected clients
	s.broadcastFromMUD(line)
	s.updateActivity()
}

// broadcastFromMUD sends a line to all connected clients
func (s *Session) broadcastFromMUD(line buffer.Line) {
	message := map[string]interface{}{
		"type":      "fromMud",
		"lineId":    line.LineID,
		"text":      line.Text,
		"timestamp": line.Timestamp,
	}

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for client := range s.clients {
		select {
		case client.SendChan <- mustMarshalJSON(message):
		default:
			// Client's send buffer is full, skip
		}
	}
}

// BroadcastStatus sends status update to all connected clients
func (s *Session) BroadcastStatus() {
	info := s.GetInfo()
	message := map[string]interface{}{
		"type":      "status",
		"connected": s.IsConnected(),
		"mudHost":   info["mudHost"],
		"mudPort":   info["mudPort"],
		"sessionId": info["sessionId"],
		"uptime":    info["uptime"],
		"timestamp": time.Now().Unix(),
	}

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for client := range s.clients {
		select {
		case client.SendChan <- mustMarshalJSON(message):
		default:
			// Client's send buffer is full, skip
		}
	}
}

// BroadcastSystemMessage sends a system message to all connected clients as a fromMud message
// so it displays inline in their MUD output.
func (s *Session) BroadcastSystemMessage(text string) {
	line := s.buffer.Append(text)

	message := map[string]interface{}{
		"type":      "fromMud",
		"lineId":    line.LineID,
		"text":      line.Text,
		"timestamp": line.Timestamp,
	}

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for client := range s.clients {
		select {
		case client.SendChan <- mustMarshalJSON(message):
		default:
		}
	}
}

// AddClient registers a client to receive broadcasts
func (s *Session) AddClient(client *Client) {
	s.clientsMu.Lock()
	s.clients[client] = true
	clientCount := len(s.clients)
	s.clientsMu.Unlock()

	s.mu.Lock()
	s.lastClientActivity = time.Now()
	s.mu.Unlock()

	log.Printf("[Session %s] Client %s added (%d total)", s.id, client.ID, clientCount)
}

// RemoveClient unregisters a client
func (s *Session) RemoveClient(client *Client) {
	s.clientsMu.Lock()
	delete(s.clients, client)
	clientCount := len(s.clients)
	s.clientsMu.Unlock()

	s.mu.Lock()
	s.lastClientActivity = time.Now()
	s.mu.Unlock()

	log.Printf("[Session %s] Client %s removed (%d remaining)", s.id, client.ID, clientCount)
}

// GetBacklog returns lines since the given lineID
func (s *Session) GetBacklog(sinceLineID int64, maxLines int) []buffer.Line {
	return s.buffer.GetSince(sinceLineID, maxLines)
}

// GetCurrentLineID returns the current line ID
func (s *Session) GetCurrentLineID() int64 {
	return s.buffer.GetCurrentLineID()
}

// IsConnected returns whether the session is connected to the MUD
func (s *Session) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mudConnected
}

// GetUptime returns how long the session has been connected to the MUD
func (s *Session) GetUptime() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.mudConnected {
		return 0
	}
	return int64(time.Since(s.mudConnectedAt).Seconds())
}

// updateActivity updates the last activity timestamp
func (s *Session) updateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
}

// LastActivity returns the last activity time
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// HasClients returns whether any clients are connected
func (s *Session) HasClients() bool {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()
	return len(s.clients) > 0
}

// ShouldDisconnectMUD returns true if MUD should be disconnected (no clients and exceeded MUD idle timeout)
func (s *Session) ShouldDisconnectMUD() bool {
	s.clientsMu.RLock()
	hasClients := len(s.clients) > 0
	s.clientsMu.RUnlock()

	if hasClients {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Disconnect MUD if no clients and MUD idle timeout exceeded
	return s.mudConnected && time.Since(s.lastClientActivity) > s.mudIdleTimeout
}

// IsIdle returns true if the session should be completely removed (exceeded buffer timeout)
func (s *Session) IsIdle() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Keep session alive as long as it's within buffer timeout from creation
	return time.Since(s.createdAt) > s.bufferTimeout
}

// Close shuts down the session
func (s *Session) Close() {
	log.Printf("[Session %s] Closing session", s.id)
	s.cancel()
	s.DisconnectFromMUD()
	s.buffer.Clear()

	s.clientsMu.Lock()
	s.clients = make(map[*Client]bool)
	s.clientsMu.Unlock()
}

// GetInfo returns session information
func (s *Session) GetInfo() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Calculate uptime inline to avoid deadlock (can't call GetUptime while holding lock)
	var uptime int64
	if s.mudConnected {
		uptime = int64(time.Since(s.mudConnectedAt).Seconds())
	}

	return map[string]interface{}{
		"sessionId": s.id,
		"mudHost":   s.mudHost,
		"mudPort":   s.mudPort,
		"connected": s.mudConnected,
		"uptime":    uptime,
	}
}
