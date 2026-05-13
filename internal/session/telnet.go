package session

// Telnet protocol constants
const (
	telnetIAC  byte = 255 // Interpret As Command
	telnetSB   byte = 250 // Subnegotiation Begin
	telnetSE   byte = 240 // Subnegotiation End
	telnetWILL byte = 251
	telnetWONT byte = 252
	telnetDO   byte = 253
	telnetDONT byte = 254
)

// Telnet option constants
const (
	optECHO    byte = 1
	optSGA     byte = 3
	optTTYPE   byte = 24
	optNAWS    byte = 31
	optCHARSET byte = 42
	optMSDP    byte = 69
	optGMCP    byte = 201
)

// MSDP sub-negotiation byte codes (RFC / MSDP spec)
const (
	msdpVAR         byte = 1
	msdpVAL         byte = 2
	msdpTABLE_OPEN  byte = 3
	msdpTABLE_CLOSE byte = 4
	msdpARRAY_OPEN  byte = 5
	msdpARRAY_CLOSE byte = 6
)

// telnetState represents the current state of the telnet parser state machine.
type telnetState int

const (
	stateData  telnetState = iota // Normal data passthrough
	stateIAC                      // Received IAC, waiting for command byte
	stateWill                     // IAC WILL, waiting for option byte
	stateWont                     // IAC WONT, waiting for option byte
	stateDo                       // IAC DO, waiting for option byte
	stateDont                     // IAC DONT, waiting for option byte
	stateSB                       // Inside subnegotiation, collecting bytes
	stateSBIAC                    // Inside subneg, received IAC (could be SE or escaped 0xFF)
)

// TelnetParser is a byte-at-a-time state machine that processes the telnet
// protocol. It persists its state between calls to Process(), so IAC sequences
// split across TCP packet boundaries are handled correctly.
type TelnetParser struct {
	state       telnetState
	sbBuf       []byte        // accumulated subnegotiation payload
	session     *Session      // back-pointer for sending responses
	optDoSent   map[byte]bool // options for which we have already sent DO (server-side)
	optWillSent map[byte]bool // options for which we have already sent WILL (client-side)
}

// NewTelnetParser creates a new telnet parser bound to the given session.
func NewTelnetParser(s *Session) *TelnetParser {
	return &TelnetParser{
		state:       stateData,
		sbBuf:       make([]byte, 0, 64),
		session:     s,
		optDoSent:   make(map[byte]bool),
		optWillSent: make(map[byte]bool),
	}
}

// Reset clears parser state. Must be called when the MUD TCP connection is
// re-established so stale partial sequences from a previous connection are
// not carried over.
func (p *TelnetParser) Reset() {
	p.state = stateData
	p.sbBuf = p.sbBuf[:0]
	p.optDoSent = make(map[byte]bool)
	p.optWillSent = make(map[byte]bool)
}

// Process feeds a chunk of raw bytes from the MUD through the state machine.
// It returns the cleaned data with all telnet IAC sequences stripped, and
// dispatches appropriate responses for negotiation commands.
func (p *TelnetParser) Process(data []byte) []byte {
	result := make([]byte, 0, len(data))

	for _, b := range data {
		switch p.state {
		case stateData:
			if b == telnetIAC {
				p.state = stateIAC
			} else {
				result = append(result, b)
			}

		case stateIAC:
			switch b {
			case telnetIAC: // Escaped IAC → literal 0xFF
				result = append(result, 0xFF)
				p.state = stateData
			case telnetSB:
				p.sbBuf = p.sbBuf[:0]
				p.state = stateSB
			case telnetWILL:
				p.state = stateWill
			case telnetWONT:
				p.state = stateWont
			case telnetDO:
				p.state = stateDo
			case telnetDONT:
				p.state = stateDont
			default:
				// Two-byte IAC command (GA, NOP, AYT, etc.) — consume silently
				p.state = stateData
			}

		case stateWill:
			p.handleWill(b)
			p.state = stateData

		case stateWont:
			// Server refuses an option — no response required
			p.state = stateData

		case stateDo:
			p.handleDo(b)
			p.state = stateData

		case stateDont:
			// Server tells us not to do something — no response required
			p.state = stateData

		case stateSB:
			if b == telnetIAC {
				p.state = stateSBIAC
			} else {
				p.sbBuf = append(p.sbBuf, b)
			}

		case stateSBIAC:
			switch b {
			case telnetSE:
				// End of subnegotiation
				p.handleSubnegotiation(p.sbBuf)
				p.sbBuf = p.sbBuf[:0]
				p.state = stateData
			case telnetIAC:
				// Escaped 0xFF inside subnegotiation
				p.sbBuf = append(p.sbBuf, 0xFF)
				p.state = stateSB
			default:
				// Unexpected byte after IAC inside subneg — shouldn't happen
				// in well-formed telnet, but be resilient and keep collecting
				p.sbBuf = append(p.sbBuf, b)
				p.state = stateSB
			}
		}
	}

	return result
}

// handleWill responds to IAC WILL <option> from the server.
// Ateraan-safe: only accept SGA and ECHO (fundamental telnet). Refuse everything
// else (GMCP, MSDP, TTYPE, NAWS, CHARSET, etc.) to avoid crashing legacy drivers.
func (p *TelnetParser) handleWill(option byte) {
	if p.optDoSent[option] {
		return
	}
	switch option {
	case optSGA, optECHO:
		p.session.sendTelnetResponse([]byte{telnetIAC, telnetDO, option})
		p.optDoSent[option] = true
	default:
		p.session.sendTelnetResponse([]byte{telnetIAC, telnetDONT, option})
	}
}

// handleDo responds to IAC DO <option> from the server.
// Ateraan-safe: only accept SGA (fundamental telnet). Refuse everything else
// (TTYPE, NAWS, GMCP, MSDP, CHARSET, etc.) to avoid crashing legacy drivers.
func (p *TelnetParser) handleDo(option byte) {
	if p.optWillSent[option] {
		return
	}
	switch option {
	case optSGA:
		p.session.sendTelnetResponse([]byte{telnetIAC, telnetWILL, optSGA})
		p.optWillSent[option] = true
	default:
		p.session.sendTelnetResponse([]byte{telnetIAC, telnetWONT, option})
	}
}

// handleSubnegotiation dispatches a completed subnegotiation payload.
// Ateraan-safe: we never accept any option that uses subnegotiation, so this
// should never fire. No-op as a safety net.
func (p *TelnetParser) handleSubnegotiation(sbData []byte) {
}
