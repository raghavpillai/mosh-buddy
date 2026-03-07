package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	msg := &Message{
		Type:      "exec",
		SessionID: "abc-123",
		Command:   "open",
		Args:      []string{"https://example.com"},
		Stdin:     []byte("hello"),
		Timestamp: 1700000000,
		HMAC:      "deadbeef",
		Port:      4445,
		Key:       "cafebabe",
		Error:     "",
	}

	var buf bytes.Buffer
	if err := Encode(&buf, msg); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got.Type != msg.Type {
		t.Errorf("Type: got %q, want %q", got.Type, msg.Type)
	}
	if got.SessionID != msg.SessionID {
		t.Errorf("SessionID: got %q, want %q", got.SessionID, msg.SessionID)
	}
	if got.Command != msg.Command {
		t.Errorf("Command: got %q, want %q", got.Command, msg.Command)
	}
	if len(got.Args) != len(msg.Args) || got.Args[0] != msg.Args[0] {
		t.Errorf("Args: got %v, want %v", got.Args, msg.Args)
	}
	if !bytes.Equal(got.Stdin, msg.Stdin) {
		t.Errorf("Stdin: got %v, want %v", got.Stdin, msg.Stdin)
	}
	if got.Timestamp != msg.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", got.Timestamp, msg.Timestamp)
	}
	if got.HMAC != msg.HMAC {
		t.Errorf("HMAC: got %q, want %q", got.HMAC, msg.HMAC)
	}
}

func TestCanonicalPayloadDeterministic(t *testing.T) {
	msg := &Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://example.com"},
		Timestamp: 1700000000,
	}
	a := CanonicalPayload(msg)
	b := CanonicalPayload(msg)
	if !bytes.Equal(a, b) {
		t.Errorf("canonical payload not deterministic")
	}
}

func TestCanonicalPayloadDifferentArgs(t *testing.T) {
	msg1 := &Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://a.com"},
		Timestamp: 1700000000,
	}
	msg2 := &Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://b.com"},
		Timestamp: 1700000000,
	}
	if bytes.Equal(CanonicalPayload(msg1), CanonicalPayload(msg2)) {
		t.Errorf("different args should produce different canonical payloads")
	}
}

func TestMaxSize(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(MaxMessageSize+1))
	buf.Write(make([]byte, 100)) // doesn't matter, should reject before reading

	_, err := Decode(&buf)
	if err == nil {
		t.Fatalf("expected error for oversized message")
	}
}

func TestTruncatedLength(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00, 0x00}) // only 2 bytes, need 4
	_, err := Decode(buf)
	if err == nil {
		t.Fatalf("expected error for truncated length prefix")
	}
}

func TestInvalidJSON(t *testing.T) {
	payload := []byte("not json at all{{{")
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(payload))) //nolint:gosec // test data, len is small
	buf.Write(payload)

	_, err := Decode(&buf)
	if err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
}

func TestCanonicalPayloadIncludesStdin(t *testing.T) {
	base := &Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "pbcopy",
		Timestamp: 1700000000,
	}
	withStdin := &Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "pbcopy",
		Stdin:     []byte("hello"),
		Timestamp: 1700000000,
	}
	if bytes.Equal(CanonicalPayload(base), CanonicalPayload(withStdin)) {
		t.Errorf("messages with different stdin should have different canonical payloads")
	}
}

func TestValidateSessionID(t *testing.T) {
	valid := "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
	if err := ValidateSessionID(valid); err != nil {
		t.Errorf("valid UUID rejected: %v", err)
	}

	for _, bad := range []string{
		"",
		"../../../etc/passwd",
		"not-a-uuid",
		"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5", // too short
		"A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D", // uppercase
	} {
		if err := ValidateSessionID(bad); err == nil {
			t.Errorf("ValidateSessionID(%q) should fail", bad)
		}
	}
}

func TestNilVsEmptyArgs(t *testing.T) {
	msg1 := &Message{Type: "exec", SessionID: "s", Command: "open", Args: nil, Timestamp: 1}
	msg2 := &Message{Type: "exec", SessionID: "s", Command: "open", Args: []string{}, Timestamp: 1}

	var buf1, buf2 bytes.Buffer
	if err := Encode(&buf1, msg1); err != nil {
		t.Fatalf("Encode msg1: %v", err)
	}
	if err := Encode(&buf2, msg2); err != nil {
		t.Fatalf("Encode msg2: %v", err)
	}

	got1, _ := Decode(&buf1)
	got2, _ := Decode(&buf2)

	// Both should decode without error; args may differ in nil vs empty but canonical payload should be same
	cp1 := CanonicalPayload(got1)
	cp2 := CanonicalPayload(got2)
	if !bytes.Equal(cp1, cp2) {
		t.Errorf("nil and empty args should produce same canonical payload, got %q vs %q", cp1, cp2)
	}
}
