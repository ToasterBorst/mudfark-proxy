package session

import (
	"encoding/json"
	"strconv"
)

// msdpVar holds a single parsed MSDP variable name and its JSON-converted value.
type msdpVar struct {
	Name  string
	Value json.RawMessage
}

// parseMSDPVars parses a raw MSDP subnegotiation payload (the bytes after the
// leading optMSDP byte has been stripped) into a slice of name/value pairs.
//
// MSDP binary format at the top level:
//
//	MSDP_VAR <name bytes> MSDP_VAL <value bytes> [MSDP_VAR …]
//
// Values may themselves be MSDP_TABLE or MSDP_ARRAY structures.
func parseMSDPVars(payload []byte) []msdpVar {
	var vars []msdpVar
	i := 0
	for i < len(payload) {
		// Expect MSDP_VAR
		if payload[i] != msdpVAR {
			i++
			continue
		}
		i++ // consume MSDP_VAR byte

		// Read variable name (bytes until MSDP_VAL or end)
		nameStart := i
		for i < len(payload) && payload[i] != msdpVAL {
			i++
		}
		name := string(payload[nameStart:i])
		if i >= len(payload) {
			break
		}
		i++ // consume MSDP_VAL byte

		// Read value
		val, advance := parseMSDPValue(payload, i)
		i = advance

		if name != "" {
			vars = append(vars, msdpVar{Name: name, Value: val})
		}
	}
	return vars
}

// parseMSDPValue parses a single MSDP value starting at payload[pos] and
// returns the JSON-encoded value together with the new position in the slice.
//
// Handles three value forms:
//   - MSDP_TABLE_OPEN … MSDP_TABLE_CLOSE  → JSON object
//   - MSDP_ARRAY_OPEN … MSDP_ARRAY_CLOSE  → JSON array
//   - plain bytes                          → JSON number if numeric, else JSON string
func parseMSDPValue(payload []byte, pos int) (json.RawMessage, int) {
	if pos >= len(payload) {
		return json.RawMessage(`null`), pos
	}

	switch payload[pos] {
	case msdpTABLE_OPEN:
		return parseMSDPTable(payload, pos+1)

	case msdpARRAY_OPEN:
		return parseMSDPArray(payload, pos+1)

	default:
		// Plain scalar: collect bytes until the next structural token or end
		start := pos
		for pos < len(payload) && !isMSDPStructural(payload[pos]) {
			pos++
		}
		raw := payload[start:pos]
		return msdpScalarJSON(raw), pos
	}
}

// parseMSDPTable reads VAR/VAL pairs until MSDP_TABLE_CLOSE, returning a JSON object.
func parseMSDPTable(payload []byte, pos int) (json.RawMessage, int) {
	obj := make(map[string]json.RawMessage)
	for pos < len(payload) {
		if payload[pos] == msdpTABLE_CLOSE {
			pos++ // consume close
			break
		}
		if payload[pos] != msdpVAR {
			pos++
			continue
		}
		pos++ // consume MSDP_VAR

		nameStart := pos
		for pos < len(payload) && payload[pos] != msdpVAL {
			pos++
		}
		name := string(payload[nameStart:pos])
		if pos >= len(payload) {
			break
		}
		pos++ // consume MSDP_VAL

		val, newPos := parseMSDPValue(payload, pos)
		pos = newPos
		if name != "" {
			obj[name] = val
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return json.RawMessage(`{}`), pos
	}
	return json.RawMessage(b), pos
}

// parseMSDPArray reads VAL entries until MSDP_ARRAY_CLOSE, returning a JSON array.
func parseMSDPArray(payload []byte, pos int) (json.RawMessage, int) {
	var items []json.RawMessage
	for pos < len(payload) {
		if payload[pos] == msdpARRAY_CLOSE {
			pos++ // consume close
			break
		}
		if payload[pos] == msdpVAL {
			pos++ // consume MSDP_VAL separator
			val, newPos := parseMSDPValue(payload, pos)
			pos = newPos
			items = append(items, val)
			continue
		}
		pos++
	}
	b, err := json.Marshal(items)
	if err != nil {
		return json.RawMessage(`[]`), pos
	}
	return json.RawMessage(b), pos
}

// msdpScalarJSON converts a raw MSDP byte slice to a JSON value.
// Integer and float strings are emitted as JSON numbers; everything else as a
// JSON string. An empty slice becomes JSON null.
func msdpScalarJSON(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`null`)
	}
	s := string(raw)
	// Try integer first (most common for vitals like HP, MANA)
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return json.RawMessage(s)
	}
	// Try float
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return json.RawMessage(s)
	}
	// Fall back to quoted JSON string
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return json.RawMessage(b)
}

// isMSDPStructural returns true for bytes that delimit MSDP value boundaries.
func isMSDPStructural(b byte) bool {
	switch b {
	case msdpVAR, msdpVAL,
		msdpTABLE_OPEN, msdpTABLE_CLOSE,
		msdpARRAY_OPEN, msdpARRAY_CLOSE:
		return true
	}
	return false
}
