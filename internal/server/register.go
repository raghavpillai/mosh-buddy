package server

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/raghav/mosh-buddy/internal/protocol"
	"github.com/raghav/mosh-buddy/internal/security"
)

func Register(args []string) error {
	fs := flag.NewFlagSet("_register", flag.ExitOnError)
	session := fs.String("session", "", "session UUID")
	port := fs.Int("port", 0, "tunnel port")
	key := fs.String("key", "", "hex-encoded HMAC key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Read key from stdin if not provided as flag (avoids exposure in ps output)
	if *key == "" {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			k := strings.TrimSpace(scanner.Text())
			key = &k
		}
	}

	if *session == "" || *port == 0 || *key == "" {
		return fmt.Errorf("usage: mb _register --session=UUID --port=PORT [--key=KEY or key via stdin]")
	}

	// Validate key
	if _, err := security.KeyFromHex(*key); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	// Store key to disk
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	keyDir := filepath.Join(homeDir, ".mb", "sessions", *session)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "key"), []byte(*key), 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	// Connect to server daemon
	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to server daemon: %w", err)
	}
	defer conn.Close()

	// Send register message
	msg := &protocol.Message{
		Type:      "register",
		SessionID: *session,
		Port:      *port,
		Key:       *key,
	}
	if err := protocol.Encode(conn, msg); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	// Read response
	resp, err := protocol.Decode(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Type == "error" {
		return fmt.Errorf("registration failed: %s", resp.Error)
	}

	log.Printf("session %s registered on port %d", *session, *port)
	return nil
}

func Deregister(args []string) error {
	fs := flag.NewFlagSet("_deregister", flag.ExitOnError)
	session := fs.String("session", "", "session UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *session == "" {
		return fmt.Errorf("usage: mb _deregister --session=UUID")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	// Remove session key from disk
	keyDir := filepath.Join(homeDir, ".mb", "sessions", *session)
	os.RemoveAll(keyDir)

	// Connect to server daemon and send deregister
	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		// Server daemon may not be running, that's fine — disk cleanup is enough
		log.Printf("server daemon not reachable, disk cleanup done")
		return nil
	}
	defer conn.Close()

	msg := &protocol.Message{
		Type:      "deregister",
		SessionID: *session,
	}
	if err := protocol.Encode(conn, msg); err != nil {
		return fmt.Errorf("send deregister: %w", err)
	}

	resp, err := protocol.Decode(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Type == "error" {
		return fmt.Errorf("deregistration failed: %s", resp.Error)
	}

	log.Printf("session %s deregistered", *session)
	return nil
}
