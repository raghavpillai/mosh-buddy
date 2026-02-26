package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/raghav/mosh-buddy/internal/security"
)

func Connect(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mb connect user@host")
	}
	target := args[0]

	sessionID, err := generateUUID()
	if err != nil {
		return fmt.Errorf("generate session ID: %w", err)
	}

	key, err := security.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	hexKey := security.KeyToHex(key)

	log.Printf("session %s created", sessionID)

	clientPort := 4444
	if err := ensureClientDaemon(clientPort); err != nil {
		return fmt.Errorf("ensure client daemon: %w", err)
	}

	tunnelPort, err := findFreePort(4445, 4545)
	if err != nil {
		return fmt.Errorf("find free tunnel port: %w", err)
	}
	log.Printf("using tunnel port %d", tunnelPort)

	// Key passed via stdin to avoid ps visibility
	registerCmd := fmt.Sprintf("mb _register --session=%s --port=%d", sessionID, tunnelPort)
	log.Printf("registering session on %s", target)
	cmd := exec.Command("ssh", target, registerCmd)
	cmd.Stdin = strings.NewReader(hexKey + "\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("register session: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	keyDir := filepath.Join(homeDir, ".mb", "sessions", sessionID)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "key"), []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("store key: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	go tunnelMonitor(ctx, target, tunnelPort, clientPort, sessionID, hexKey)

	mbUser := ""
	mbHost := target
	if i := strings.Index(target, "@"); i >= 0 {
		mbUser = target[:i]
		mbHost = target[i+1:]
	}
	moshServer := fmt.Sprintf("env MB_SESSION=%s MB_PORT=%d MB_HOST=%s MB_USER=%s mosh-server",
		sessionID, tunnelPort, mbHost, mbUser)
	moshCmd := exec.Command("mosh", "--server="+moshServer, target)
	moshCmd.Stdin = os.Stdin
	moshCmd.Stdout = os.Stdout
	moshCmd.Stderr = os.Stderr

	log.Printf("launching mosh to %s", target)
	moshErr := moshCmd.Run()

	cancel()
	cleanup(target, sessionID, homeDir)

	if moshErr != nil {
		return fmt.Errorf("mosh: %w", moshErr)
	}
	return nil
}

func tunnelMonitor(ctx context.Context, target string, tunnelPort, clientPort int, sessionID, hexKey string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tunnelArg := fmt.Sprintf("%d:localhost:%d", tunnelPort, clientPort)
		cmd := exec.CommandContext(ctx, "ssh", "-N",
			"-R", tunnelArg,
			"-o", "ServerAliveInterval=10",
			"-o", "ServerAliveCountMax=3",
			"-o", "ExitOnForwardFailure=yes",
			target,
		)

		log.Printf("starting SSH tunnel (remote port %d → local port %d)", tunnelPort, clientPort)
		err := cmd.Run()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("tunnel exited: %v, reconnecting in 2s...", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		// Re-register in case port changed (for now same port)
		registerCmd := fmt.Sprintf("mb _register --session=%s --port=%d", sessionID, tunnelPort)
		reReg := exec.Command("ssh", target, registerCmd)
		reReg.Stdin = strings.NewReader(hexKey + "\n")
		_ = reReg.Run() // best-effort
	}
}

func ensureClientDaemon(port int) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err == nil {
		conn.Close()
		log.Printf("client daemon already running on port %d", port)
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	cmd := exec.Command(exe, "client-daemon", fmt.Sprintf("--port=%d", port))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start client daemon: %w", err)
	}

	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			log.Printf("client daemon started on port %d", port)
			return nil
		}
	}
	return fmt.Errorf("client daemon didn't start within 2 seconds")
}

func findFreePort(start, end int) (int, error) {
	for port := start; port <= end; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free port in range %d-%d", start, end)
}

func cleanup(target, sessionID, homeDir string) {
	log.Printf("cleaning up session %s", sessionID)

	keyDir := filepath.Join(homeDir, ".mb", "sessions", sessionID)
	os.RemoveAll(keyDir)

	// Best-effort deregister cleans both disk and in-memory state
	cmd := exec.Command("ssh", target, fmt.Sprintf("mb _deregister --session=%s", sessionID))
	_ = cmd.Run()
}

func generateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", err
	}
	// Version 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Variant 1
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}
