package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mudlark-app/mudlark-proxy/internal/auth"
	"github.com/mudlark-app/mudlark-proxy/internal/session"
)

const maxMessageSize = 64 * 1024 // 64KB max WebSocket message size

// newUpgrader creates a WebSocket upgrader with origin checking
func newUpgrader(allowedOrigins []string) websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			// If no origins configured, allow all (development mode)
			if len(allowedOrigins) == 0 {
				return true
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Native apps (iOS) typically don't send Origin headers
				return true
			}
			for _, allowed := range allowedOrigins {
				if strings.EqualFold(origin, allowed) {
					return true
				}
			}
			log.Printf("Rejected WebSocket connection from origin: %s", origin)
			return false
		},
	}
}

// isExpectedWebSocketError returns true for errors that indicate normal client disconnect
func isExpectedWebSocketError(err error) bool {
	if err == nil {
		return false
	}

	// WebSocket close errors are expected
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseAbnormalClosure) {
		return true
	}

	// Network errors indicating disconnect
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		var syscallErr syscall.Errno
		if errors.As(netErr.Err, &syscallErr) {
			switch syscallErr {
			case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.ENOTCONN:
				return true
			}
		}
		if netErr.Err != nil && strings.Contains(netErr.Err.Error(), "use of closed network connection") {
			return true
		}
	}

	// Check error message for common disconnect patterns
	errMsg := strings.ToLower(err.Error())
	expectedMessages := []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"connection abort",
	}
	for _, msg := range expectedMessages {
		if strings.Contains(errMsg, msg) {
			return true
		}
	}

	return false
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check for JWT in Authorization header (preferred for server-minted tokens)
	var headerJWT string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		headerJWT = strings.TrimPrefix(authHeader, "Bearer ")
	}

	upgrader := newUpgrader(s.config.Auth.AllowedOrigins)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Limit message size to prevent memory abuse
	conn.SetReadLimit(maxMessageSize)
	defer conn.Close()

	// Wait for hello message
	hello, err := s.readHello(conn)
	if err != nil {
		s.sendError(conn, "INVALID_MESSAGE", err.Error(), true)
		return
	}

	// Clear the read deadline set by readHello
	conn.SetReadDeadline(time.Time{})

	// Use JWT from Authorization header if available, otherwise from hello message
	jwtToken := headerJWT
	if jwtToken == "" {
		jwtToken = hello.JWT
	}
	if jwtToken == "" {
		s.sendError(conn, "AUTH_FAILED", "No authentication token provided", true)
		return
	}

	// Validate JWT
	claims, err := s.jwtValidator.ValidateToken(jwtToken)
	if err != nil {
		log.Printf("JWT validation failed: %v", err)
		s.sendError(conn, "AUTH_FAILED", "Invalid or expired token", true)
		return
	}

	// Use session ID from JWT claims (more secure than trusting client message)
	sessionID := claims.SessionID
	if sessionID == "" {
		// Fallback to hello message if JWT doesn't have sid claim
		sessionID = hello.SessionID
	}

	log.Printf("Client connecting: sessionID=%s, mudHost=%s:%d",
		sessionID, hello.MUDHost, hello.MUDPort)

	// Get or create session
	sess, isNew, err := s.sessionManager.GetOrCreate(
		sessionID,
		claims.UserID,
		hello.MUDHost,
		hello.MUDPort,
		hello.ConnectionTime,
		hello.MudIdleTimeout,
		hello.BufferTimeout,
		hello.MUDTLS,
	)
	if err != nil {
		log.Printf("Session error for userID=%s, sessionID=%s: %v", claims.UserID, sessionID, err)
		if err == session.ErrSessionConflict {
			s.sendError(conn, "SESSION_CONFLICT", "Session belongs to different user", true)
		} else {
			s.sendError(conn, "SERVER_ERROR", "Failed to create session", true)
		}
		return
	}

	// If new session or session not connected, connect to MUD
	if isNew || !sess.IsConnected() {
		if hello.MUDHost == "" || hello.MUDPort == 0 {
			s.sendError(conn, "INVALID_MESSAGE", "mudHost and mudPort required for new session", true)
			return
		}

		if err := sess.ConnectToMUD(); err != nil {
			log.Printf("Failed to connect to MUD: %v", err)
			s.sendError(conn, "MUD_UNREACHABLE", "Cannot connect to MUD server", false)
		}
	}

	// Create client
	client := &session.Client{
		ID:       claims.UserID,
		SendChan: make(chan []byte, 256),
	}

	sess.AddClient(client)
	defer func() {
		sess.RemoveClient(client)
		close(client.SendChan) // Signal write pump to stop
	}()

	// Set initial window size from hello message
	if hello.WindowWidth > 0 && hello.WindowHeight > 0 {
		sess.UpdateWindowSize(hello.WindowWidth, hello.WindowHeight)
	}

	// Send backlog if requested
	if hello.ResumeFrom > 0 {
		backlog := sess.GetBacklog(hello.ResumeFrom, s.config.Buffer.MaxReplay)

		// Convert to interface{} slice for JSON
		backlogInterface := make([]interface{}, len(backlog))
		for i, line := range backlog {
			backlogInterface[i] = map[string]interface{}{
				"lineId":    line.LineID,
				"text":      line.Text,
				"timestamp": line.Timestamp,
			}
		}

		s.sendBacklog(conn, backlogInterface, hello.ResumeFrom, sess.GetCurrentLineID())
	}

	// Send status message
	s.sendStatus(conn, sess)

	// Create context for this connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start goroutines for reading and writing
	done := make(chan struct{})

	// Write pump: send messages from client.SendChan to WebSocket
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Session %s] Write pump panic recovered: %v", sess.ID(), r)
			}
			close(done)
		}()
		for {
			select {
			case <-ctx.Done():
				// Connection closed, stop writing
				return
			case message, ok := <-client.SendChan:
				if !ok {
					// Channel closed, stop writing
					return
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
					if !isExpectedWebSocketError(err) {
						log.Printf("[Session %s] WebSocket write error: %v", sess.ID(), err)
					}
					return
				}
			}
		}
	}()

	// Read pump: read messages from WebSocket
	// No read deadline - client can disconnect/sleep, session stays alive
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Session %s] Read pump panic recovered: %v", sess.ID(), r)
			cancel()
		}
	}()

	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			// Client disconnected
			if isExpectedWebSocketError(err) {
				log.Printf("[Session %s] Client disconnected (expected)", sess.ID())
			} else {
				log.Printf("[Session %s] Client disconnected with error: %v", sess.ID(), err)
			}
			cancel() // Signal write pump to stop
			break
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			s.sendError(conn, "INVALID_MESSAGE", "Missing 'type' field", false)
			continue
		}

		s.handleClientMessage(conn, sess, msgType, msg)
	}

	<-done
}

// readHello reads and validates the hello message
func (s *Server) readHello(conn *websocket.Conn) (*helloMessage, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// First read as raw JSON to see everything the client sends
	var rawMsg map[string]interface{}
	if err := conn.ReadJSON(&rawMsg); err != nil {
		return nil, err
	}

	// Now parse into our struct
	var msg helloMessage
	msgType, _ := rawMsg["type"].(string)
	if msgType != "hello" {
		return nil, auth.ErrInvalidToken
	}

	msg.Type = msgType
	msg.JWT, _ = rawMsg["jwt"].(string)
	msg.SessionID, _ = rawMsg["sessionId"].(string)
	if resumeFrom, ok := rawMsg["resumeFrom"].(float64); ok {
		msg.ResumeFrom = int64(resumeFrom)
	}
	msg.MUDHost, _ = rawMsg["mudHost"].(string)
	if mudPort, ok := rawMsg["mudPort"].(float64); ok {
		msg.MUDPort = int(mudPort)
	}
	msg.ClientVersion, _ = rawMsg["clientVersion"].(string)
	if connectionTime, ok := rawMsg["connectiontime"].(float64); ok {
		msg.ConnectionTime = int(connectionTime)
	}
	if mudIdleTimeout, ok := rawMsg["mudIdleTimeout"].(float64); ok {
		msg.MudIdleTimeout = int(mudIdleTimeout)
	}
	if bufferTimeout, ok := rawMsg["bufferTimeout"].(float64); ok {
		msg.BufferTimeout = int(bufferTimeout)
	}
	if windowWidth, ok := rawMsg["windowWidth"].(float64); ok {
		msg.WindowWidth = int(windowWidth)
	}
	if windowHeight, ok := rawMsg["windowHeight"].(float64); ok {
		msg.WindowHeight = int(windowHeight)
	}
	msg.MUDTLS, _ = rawMsg["mudTLS"].(bool)

	return &msg, nil
}

// handleClientMessage routes client messages to appropriate handlers
func (s *Server) handleClientMessage(conn *websocket.Conn, sess *session.Session, msgType string, msg map[string]interface{}) {
	switch msgType {
	case "toMud":
		text, ok := msg["text"].(string)
		if !ok {
			s.sendError(conn, "INVALID_MESSAGE", "Missing 'text' field", false)
			return
		}
		if err := sess.SendToMUD(text); err != nil {
			s.sendError(conn, "MUD_DISCONNECTED", "Cannot send to MUD", false)
			// Send updated status showing disconnected
			s.sendStatus(conn, sess)
		}

	case "ping":
		timestamp, _ := msg["timestamp"].(float64)
		s.sendPong(conn, int64(timestamp))

	case "disconnect":
		reason, _ := msg["reason"].(string)
		log.Printf("[Session %s] Client requested disconnect: %s", sess.ID(), reason)
		s.sessionManager.Remove(sess.ID())
		conn.Close()

	case "windowSize":
		width, _ := msg["width"].(float64)
		height, _ := msg["height"].(float64)
		if width > 0 && height > 0 {
			sess.UpdateWindowSize(int(width), int(height))
		}

	case "ack":
		// Client acknowledges receipt of lines
		// Could be used to trim buffer, but not critical for MVP

	default:
		s.sendError(conn, "INVALID_MESSAGE", "Unknown message type", false)
	}
}

// Message structures
type helloMessage struct {
	Type           string `json:"type"`
	JWT            string `json:"jwt"`
	SessionID      string `json:"sessionId"`
	ResumeFrom     int64  `json:"resumeFrom"`
	MUDHost        string `json:"mudHost"`
	MUDPort        int    `json:"mudPort"`
	ClientVersion  string `json:"clientVersion"`
	ConnectionTime int    `json:"connectiontime"`
	MudIdleTimeout int    `json:"mudIdleTimeout"` // Minutes to keep MUD connected without client (0 = use server default)
	BufferTimeout  int    `json:"bufferTimeout"`  // Minutes to keep buffer/session data (0 = use server default)
	WindowWidth    int    `json:"windowWidth"`    // Terminal width in columns (0 = use default 80)
	WindowHeight   int    `json:"windowHeight"`   // Terminal height in rows (0 = use default 24)
	MUDTLS         bool   `json:"mudTLS"`         // Whether to use TLS for MUD connection
}

// Helper functions to send messages
func (s *Server) sendStatus(conn *websocket.Conn, sess *session.Session) {
	info := sess.GetInfo()
	msg := map[string]interface{}{
		"type":      "status",
		"connected": sess.IsConnected(),
		"mudHost":   info["mudHost"],
		"mudPort":   info["mudPort"],
		"sessionId": info["sessionId"],
		"uptime":    info["uptime"],
		"timestamp": time.Now().Unix(),
	}
	s.sendJSON(conn, msg)
}

func (s *Server) sendBacklog(conn *websocket.Conn, lines []interface{}, resumedFrom, currentLineID int64) {
	msg := map[string]interface{}{
		"type":          "backlog",
		"lines":         lines,
		"resumedFrom":   resumedFrom,
		"currentLineId": currentLineID,
	}
	s.sendJSON(conn, msg)
}

func (s *Server) sendError(conn *websocket.Conn, code, message string, fatal bool) {
	msg := map[string]interface{}{
		"type":      "error",
		"code":      code,
		"message":   message,
		"fatal":     fatal,
		"timestamp": time.Now().Unix(),
	}
	s.sendJSON(conn, msg)

	if fatal {
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}
}

func (s *Server) sendPong(conn *websocket.Conn, timestamp int64) {
	msg := map[string]interface{}{
		"type":      "pong",
		"timestamp": timestamp,
	}
	s.sendJSON(conn, msg)
}

func (s *Server) sendJSON(conn *websocket.Conn, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("WebSocket write error: %v", err)
	}
}
