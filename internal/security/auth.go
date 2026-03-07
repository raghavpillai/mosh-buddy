package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}

const MinKeyLen = 32

func KeyFromHex(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) < MinKeyLen {
		return nil, fmt.Errorf("key too short: %d bytes, minimum %d", len(key), MinKeyLen)
	}
	return key, nil
}

func Sign(key []byte, msg *protocol.Message) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(protocol.CanonicalPayload(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(key []byte, msg *protocol.Message) bool {
	expected := Sign(key, msg)
	return hmac.Equal([]byte(expected), []byte(msg.HMAC))
}

func ValidateTimestamp(ts int64, maxAge time.Duration) bool {
	diff := time.Now().Unix() - ts
	return math.Abs(float64(diff)) <= maxAge.Seconds()
}
