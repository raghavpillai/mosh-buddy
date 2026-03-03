package internal

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/client"
	"github.com/raghavpillai/mosh-buddy/internal/protocol"
	"github.com/raghavpillai/mosh-buddy/internal/security"
	"github.com/raghavpillai/mosh-buddy/internal/server"
)

func TestIntegrationBasicFlow(t *testing.T) {
	// Setup temp directories
	tmpDir, err := os.MkdirTemp("", "mb-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mbDir := filepath.Join(tmpDir, ".mb")
	if err := os.MkdirAll(filepath.Join(mbDir, "sessions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mbDir, "queue"), 0700); err != nil {
		t.Fatal(err)
	}

	// Find free ports
	clientPort := findFreePort(t, 14444, 14544)
	socketPath := filepath.Join(tmpDir, "mb.sock")

	// Generate session credentials (must be valid UUID format)
	sessionID := "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
	key, _ := security.GenerateKey()
	hexKey := security.KeyToHex(key)

	// Write config that allows "echo"
	configData := `{"allow": ["echo", "true", "open", "xdg-open", "pbcopy", "notify-send"], "deny": ["rm", "sudo"], "prompt_unknown": false}`
	if err := os.WriteFile(filepath.Join(mbDir, "config.json"), []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	// Store session key in client's session dir
	keyDir := filepath.Join(mbDir, "sessions", sessionID)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "key"), []byte(hexKey), 0600); err != nil {
		t.Fatal(err)
	}

	// Override HOME so daemons find our test directory
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Start client daemon
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientDaemon := client.NewClientDaemon(clientPort)
	go func() { _ = clientDaemon.Run(ctx) }()

	// Wait for client to be ready
	waitForPort(t, clientPort, 3*time.Second)

	// Start server daemon
	serverDaemon := server.NewServerDaemonWithDir(socketPath, mbDir)
	go func() { _ = serverDaemon.Run(ctx) }()

	// Wait for server to be ready
	waitForSocket(t, socketPath, 3*time.Second)

	// Register session (pointing at client port directly, simulating tunnel)
	serverDaemon.RegisterSession(sessionID, clientPort, key)

	// Send an exec command through the server daemon
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}

	msg := &protocol.Message{
		Type:      "exec",
		SessionID: sessionID,
		Command:   "true", // just exit 0
		Args:      nil,
	}
	if err := protocol.Encode(conn, msg); err != nil {
		t.Fatalf("encode: %v", err)
	}

	resp, err := protocol.Decode(conn)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	conn.Close()

	if resp.Type != "ack" {
		t.Errorf("expected ack, got %s: %s", resp.Type, resp.Error)
	}
}

func TestIntegrationQueueDrain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mb-queue-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mbDir := filepath.Join(tmpDir, ".mb")
	if err := os.MkdirAll(filepath.Join(mbDir, "sessions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mbDir, "queue"), 0700); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(tmpDir, "mb.sock")
	sessionID := "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
	key, _ := security.GenerateKey()
	hexKey := security.KeyToHex(key)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	keyDir := filepath.Join(mbDir, "sessions", sessionID)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "key"), []byte(hexKey), 0600); err != nil {
		t.Fatal(err)
	}

	configData := `{"allow": ["true", "echo"], "deny": [], "prompt_unknown": false}`
	if err := os.WriteFile(filepath.Join(mbDir, "config.json"), []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server daemon but register session on a port nothing is listening on
	serverDaemon := server.NewServerDaemonWithDir(socketPath, mbDir)
	go func() { _ = serverDaemon.Run(ctx) }()
	waitForSocket(t, socketPath, 3*time.Second)

	deadPort := 19999
	serverDaemon.RegisterSession(sessionID, deadPort, key)

	// Send a command — should be queued since tunnel is down
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	msg := &protocol.Message{
		Type:      "exec",
		SessionID: sessionID,
		Command:   "true",
	}
	if err := protocol.Encode(conn, msg); err != nil {
		t.Fatalf("encode: %v", err)
	}
	resp, err := protocol.Decode(conn)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	conn.Close()

	if resp.Type != "ack" {
		t.Fatalf("expected ack (queued), got %s: %s", resp.Type, resp.Error)
	}

	// Now start client daemon on a port and update session to point there
	clientPort := findFreePort(t, 15000, 15100)
	clientDaemon := client.NewClientDaemon(clientPort)
	go func() { _ = clientDaemon.Run(ctx) }()
	waitForPort(t, clientPort, 3*time.Second)

	// Update session to point at the real client
	serverDaemon.RegisterSession(sessionID, clientPort, key)

	// Wait for drain loop to pick it up (runs every 5 seconds)
	// Poll for completion rather than blindly sleeping
	queueDir := filepath.Join(mbDir, "queue", sessionID)
	drained := false
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		entries, err := os.ReadDir(queueDir)
		if err != nil || len(entries) == 0 {
			drained = true
			break
		}
		// Filter out .draining files (in-progress)
		pending := 0
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".json" {
				pending++
			}
		}
		if pending == 0 {
			drained = true
			break
		}
	}
	if !drained {
		t.Fatal("queue was not drained within 10 seconds")
	}
	t.Log("queue drain test passed — command was forwarded after tunnel came up")
}

func findFreePort(t *testing.T, start, end int) int {
	t.Helper()
	for port := start; port <= end; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	t.Fatalf("no free port in range %d-%d", start, end)
	return 0
}

func waitForPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d not ready within %v", port, timeout)
}

func waitForSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", path)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s not ready within %v", path, timeout)
}
