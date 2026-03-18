package buffer

import (
	"sync"
	"time"
)

// Line represents a single line from the MUD
type Line struct {
	LineID    int64  `json:"lineId"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

// RingBuffer is a thread-safe circular buffer for storing MUD output
type RingBuffer struct {
	mu       sync.RWMutex
	capacity int
	lines    []Line
	nextID   int64
	head     int // Points to the oldest item
	tail     int // Points to where next item will be inserted
	count    int // Current number of items
}

// NewRingBuffer creates a new ring buffer with the specified capacity
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		capacity: capacity,
		lines:    make([]Line, capacity),
		nextID:   1,
		head:     0,
		tail:     0,
		count:    0,
	}
}

// Append adds a new line to the buffer
func (rb *RingBuffer) Append(text string) Line {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	line := Line{
		LineID:    rb.nextID,
		Text:      text,
		Timestamp: time.Now().Unix(),
	}

	rb.lines[rb.tail] = line
	rb.nextID++

	rb.tail = (rb.tail + 1) % rb.capacity

	if rb.count < rb.capacity {
		rb.count++
	} else {
		// Buffer is full, advance head
		rb.head = (rb.head + 1) % rb.capacity
	}

	return line
}

// GetSince returns all lines with LineID > sinceLineID, up to maxLines
func (rb *RingBuffer) GetSince(sinceLineID int64, maxLines int) []Line {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.count == 0 {
		return []Line{}
	}

	result := make([]Line, 0, maxLines)

	// Iterate through the buffer
	idx := rb.head
	for i := 0; i < rb.count; i++ {
		line := rb.lines[idx]
		if line.LineID > sinceLineID {
			result = append(result, line)
			if len(result) >= maxLines {
				break
			}
		}
		idx = (idx + 1) % rb.capacity
	}

	return result
}

// GetCurrentLineID returns the most recent line ID (0 if empty)
func (rb *RingBuffer) GetCurrentLineID() int64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.count == 0 {
		return 0
	}

	return rb.nextID - 1
}

// Clear removes all lines from the buffer
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.head = 0
	rb.tail = 0
	rb.count = 0
	rb.nextID = 1
}

// Size returns the current number of lines in the buffer
func (rb *RingBuffer) Size() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}
