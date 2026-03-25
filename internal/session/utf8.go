package session

// UTF8Buffer handles reassembly of UTF-8 codepoints that may be split across
// TCP packet boundaries. It holds back incomplete trailing bytes and prepends
// them to the next chunk, exactly like TelnetParser holds partial IAC sequences.
type UTF8Buffer struct {
	carry [4]byte // incomplete codepoint bytes (max 3 needed, 4 for safety)
	n     int     // number of valid bytes in carry
}

// NewUTF8Buffer creates a new UTF-8 reassembly buffer.
func NewUTF8Buffer() *UTF8Buffer {
	return &UTF8Buffer{}
}

// Reset clears any buffered bytes. Must be called when the MUD TCP connection
// is re-established so stale partial bytes are not carried over.
func (u *UTF8Buffer) Reset() {
	u.n = 0
}

// Process takes a chunk of bytes (after telnet stripping) and returns data
// containing only complete UTF-8 codepoints. Any trailing bytes that form an
// incomplete codepoint are held internally and prepended to the next call.
func (u *UTF8Buffer) Process(data []byte) []byte {
	// Prepend carry from previous chunk
	if u.n > 0 {
		combined := make([]byte, u.n+len(data))
		copy(combined, u.carry[:u.n])
		copy(combined[u.n:], data)
		data = combined
		u.n = 0
	}

	if len(data) == 0 {
		return data
	}

	// Check if the chunk ends mid-codepoint
	tail := incompleteUTF8Tail(data)
	if tail > 0 {
		cutoff := len(data) - tail
		u.n = copy(u.carry[:], data[cutoff:])
		return data[:cutoff]
	}
	return data
}

// incompleteUTF8Tail returns the number of trailing bytes that form an
// incomplete UTF-8 codepoint, or 0 if data ends on a codepoint boundary.
func incompleteUTF8Tail(data []byte) int {
	n := len(data)
	if n == 0 {
		return 0
	}

	// Scan backwards up to 3 bytes looking for a leading byte that starts
	// a multi-byte sequence extending past the end of the data.
	maxScan := 3
	if maxScan > n {
		maxScan = n
	}

	for i := 1; i <= maxScan; i++ {
		b := data[n-i]
		if b < 0x80 {
			// ASCII byte — everything up to (and including) this byte is complete
			return 0
		}
		if b >= 0xC0 {
			// Leading byte of a multi-byte sequence
			need := utf8SeqLen(b)
			have := i // bytes from this leader to end of data
			if have < need {
				return have // incomplete — carry these bytes
			}
			return 0 // complete
		}
		// 0x80-0xBF: continuation byte, keep scanning backward
	}

	// Scanned 3 continuation bytes without finding a leading byte.
	// These are orphan continuation bytes (invalid UTF-8) — flush them.
	return 0
}

// utf8SeqLen returns the expected total byte length of a UTF-8 sequence
// given its leading byte.
func utf8SeqLen(b byte) int {
	switch {
	case b < 0xC0:
		return 1 // not a valid leading byte, treat as single
	case b < 0xE0:
		return 2
	case b < 0xF0:
		return 3
	default:
		return 4
	}
}
