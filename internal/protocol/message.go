package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const MaxMessageSize = 1 << 20 // 1 MB

var validSessionID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// ValidateSessionID checks that a session ID is a valid UUID to prevent path traversal.
func ValidateSessionID(id string) error {
	if !validSessionID.MatchString(id) {
		return fmt.Errorf("invalid session ID format: %q", id)
	}
	return nil
}

type Message struct {
	Type      string   `json:"type"`
	SessionID string   `json:"session_id"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Stdin     []byte   `json:"stdin,omitempty"`
	Timestamp int64    `json:"ts"`
	HMAC      string   `json:"hmac"`
	Port      int      `json:"port,omitempty"`
	Key       string   `json:"key,omitempty"`
	Error     string   `json:"error,omitempty"`
	Output    []byte   `json:"output,omitempty"`
}

func Encode(w io.Writer, msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(data), MaxMessageSize)
	}
	length := uint32(len(data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

func Decode(r io.Reader) (*Message, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d > %d", length, MaxMessageSize)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &msg, nil
}

func CanonicalPayload(msg *Message) []byte {
	parts := []string{
		msg.SessionID,
		msg.Type,
		msg.Command,
		strconv.Itoa(len(msg.Args)),
	}
	parts = append(parts, msg.Args...)
	parts = append(parts, strconv.FormatInt(msg.Timestamp, 10))
	return []byte(strings.Join(parts, "\n"))
}
