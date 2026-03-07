package security

import (
	"testing"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
)

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(k1) != 32 {
		t.Errorf("key length: got %d, want 32", len(k1))
	}
	k2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if string(k1) == string(k2) {
		t.Errorf("two generated keys should differ")
	}
}

func TestSignVerify(t *testing.T) {
	key, _ := GenerateKey()
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://example.com"},
		Timestamp: time.Now().Unix(),
	}
	msg.HMAC = Sign(key, msg)
	if !Verify(key, msg) {
		t.Errorf("Verify should succeed after Sign")
	}
}

func TestTamperedCommand(t *testing.T) {
	key, _ := GenerateKey()
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://example.com"},
		Timestamp: time.Now().Unix(),
	}
	msg.HMAC = Sign(key, msg)
	msg.Command = "rm"
	if Verify(key, msg) {
		t.Errorf("Verify should fail after tampering command")
	}
}

func TestTamperedArgs(t *testing.T) {
	key, _ := GenerateKey()
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://safe.com"},
		Timestamp: time.Now().Unix(),
	}
	msg.HMAC = Sign(key, msg)
	msg.Args = []string{"https://evil.com"}
	if Verify(key, msg) {
		t.Errorf("Verify should fail after tampering args")
	}
}

func TestTamperedTimestamp(t *testing.T) {
	key, _ := GenerateKey()
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://example.com"},
		Timestamp: time.Now().Unix(),
	}
	msg.HMAC = Sign(key, msg)
	msg.Timestamp = msg.Timestamp + 1000
	if Verify(key, msg) {
		t.Errorf("Verify should fail after tampering timestamp")
	}
}

func TestWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "open",
		Args:      []string{"https://example.com"},
		Timestamp: time.Now().Unix(),
	}
	msg.HMAC = Sign(key1, msg)
	if Verify(key2, msg) {
		t.Errorf("Verify should fail with wrong key")
	}
}

func TestValidateTimestampFresh(t *testing.T) {
	if !ValidateTimestamp(time.Now().Unix(), 5*time.Minute) {
		t.Errorf("fresh timestamp should be valid")
	}
}

func TestValidateTimestampStale(t *testing.T) {
	old := time.Now().Add(-6 * time.Minute).Unix()
	if ValidateTimestamp(old, 5*time.Minute) {
		t.Errorf("6-minute-old timestamp should be invalid")
	}
}

func TestValidateTimestampFuture(t *testing.T) {
	future := time.Now().Add(6 * time.Minute).Unix()
	if ValidateTimestamp(future, 5*time.Minute) {
		t.Errorf("6-minute-ahead timestamp should be invalid")
	}
}

func TestTamperedStdin(t *testing.T) {
	key, _ := GenerateKey()
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: "sess-1",
		Command:   "pbcopy",
		Stdin:     []byte("sensitive data"),
		Timestamp: time.Now().Unix(),
	}
	msg.HMAC = Sign(key, msg)
	msg.Stdin = []byte("replaced data")
	if Verify(key, msg) {
		t.Errorf("Verify should fail after tampering stdin")
	}
}

func TestKeyFromHexMinLength(t *testing.T) {
	// 16 bytes (too short, minimum is 32)
	_, err := KeyFromHex("0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Errorf("KeyFromHex should reject 16-byte key")
	}

	// 32 bytes (exactly minimum)
	_, err = KeyFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Errorf("KeyFromHex should accept 32-byte key: %v", err)
	}
}

func TestKeyHexRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	hexStr := KeyToHex(key)
	decoded, err := KeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("KeyFromHex: %v", err)
	}
	if string(key) != string(decoded) {
		t.Errorf("key round-trip failed")
	}
}
