package session

type ansiState int

const (
	ansiNormal ansiState = iota // Passing through normal data
	ansiESC                     // Received ESC (0x1B), determining sequence type
	ansiCSI                     // Inside CSI sequence (ESC [), collecting parameters
	ansiNF                      // Inside nF escape (ESC + intermediate bytes 0x20-0x2F)
	ansiOSC                     // Inside OSC sequence (ESC ]), collecting payload
	ansiOSCESC                  // Inside OSC, received ESC, checking for ST (\)
)

// maxANSISeqLen is a safety limit to prevent unbounded buffering from
// malformed input. Any sequence exceeding this is flushed as literal text.
const maxANSISeqLen = 256

// ANSIParser is a byte-at-a-time state machine that ensures ANSI escape
// sequences are not split across chunk boundaries. Unlike the telnet parser
// which strips IAC sequences, this parser preserves escape sequences intact —
// it only buffers incomplete sequences between Process() calls so they are
// always emitted as complete units.
type ANSIParser struct {
	state  ansiState
	seqBuf []byte // accumulated bytes of the current incomplete escape sequence
}

// NewANSIParser creates a new ANSI escape sequence parser.
func NewANSIParser() *ANSIParser {
	return &ANSIParser{
		state:  ansiNormal,
		seqBuf: make([]byte, 0, 64),
	}
}

// Reset clears parser state. Must be called when the MUD TCP connection is
// re-established so stale partial sequences are not carried over.
func (p *ANSIParser) Reset() {
	p.state = ansiNormal
	p.seqBuf = p.seqBuf[:0]
}

// Process feeds a chunk of bytes through the state machine and returns bytes
// with only complete ANSI escape sequences. Any partial sequence at the end
// of the chunk is held internally and will be completed by the next call.
func (p *ANSIParser) Process(data []byte) []byte {
	result := make([]byte, 0, len(data))

	for _, b := range data {
		switch p.state {
		case ansiNormal:
			if b == 0x1B {
				p.seqBuf = append(p.seqBuf[:0], b)
				p.state = ansiESC
			} else {
				result = append(result, b)
			}

		case ansiESC:
			p.seqBuf = append(p.seqBuf, b)
			switch {
			case b == '[':
				p.state = ansiCSI
			case b == ']':
				p.state = ansiOSC
			case b >= 0x20 && b <= 0x2F:
				// Intermediate byte — nF escape, need final byte(s)
				p.state = ansiNF
			case b >= 0x30 && b <= 0x7E:
				// Complete two-byte escape (Fp/Fe/Fs like ESC c, ESC M, etc.)
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			default:
				// Not a valid escape introducer — flush ESC + byte as literal
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			}

		case ansiCSI:
			switch {
			case b == 0x1B:
				// New ESC interrupts incomplete CSI — flush old, start new
				result = append(result, p.seqBuf...)
				p.seqBuf = append(p.seqBuf[:0], b)
				p.state = ansiESC
			case b >= 0x20 && b <= 0x3F:
				// Parameter byte (0x30-0x3F) or intermediate byte (0x20-0x2F)
				p.seqBuf = append(p.seqBuf, b)
				if len(p.seqBuf) > maxANSISeqLen {
					result = append(result, p.seqBuf...)
					p.seqBuf = p.seqBuf[:0]
					p.state = ansiNormal
				}
			case b >= 0x40 && b <= 0x7E:
				// Final byte — CSI sequence complete (m, A, H, J, K, etc.)
				p.seqBuf = append(p.seqBuf, b)
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			default:
				// Invalid byte terminates the sequence — flush as literal
				p.seqBuf = append(p.seqBuf, b)
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			}

		case ansiNF:
			switch {
			case b == 0x1B:
				// New ESC interrupts nF sequence
				result = append(result, p.seqBuf...)
				p.seqBuf = append(p.seqBuf[:0], b)
				p.state = ansiESC
			case b >= 0x20 && b <= 0x2F:
				// More intermediate bytes
				p.seqBuf = append(p.seqBuf, b)
				if len(p.seqBuf) > maxANSISeqLen {
					result = append(result, p.seqBuf...)
					p.seqBuf = p.seqBuf[:0]
					p.state = ansiNormal
				}
			case b >= 0x30 && b <= 0x7E:
				// Final byte — nF sequence complete
				p.seqBuf = append(p.seqBuf, b)
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			default:
				// Invalid byte — flush as literal
				p.seqBuf = append(p.seqBuf, b)
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			}

		case ansiOSC:
			switch {
			case b == 0x07:
				// BEL terminates OSC
				p.seqBuf = append(p.seqBuf, b)
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			case b == 0x1B:
				// Could be ST (ESC \)
				p.seqBuf = append(p.seqBuf, b)
				p.state = ansiOSCESC
			default:
				p.seqBuf = append(p.seqBuf, b)
				if len(p.seqBuf) > maxANSISeqLen {
					result = append(result, p.seqBuf...)
					p.seqBuf = p.seqBuf[:0]
					p.state = ansiNormal
				}
			}

		case ansiOSCESC:
			p.seqBuf = append(p.seqBuf, b)
			if b == '\\' {
				// ST (ESC \) — OSC sequence complete
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			} else {
				// ESC was not part of ST — flush entire accumulated data as literal
				result = append(result, p.seqBuf...)
				p.seqBuf = p.seqBuf[:0]
				p.state = ansiNormal
			}
		}
	}

	return result
}
