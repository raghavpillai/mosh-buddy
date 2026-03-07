package server

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/raghavpillai/mosh-buddy/internal/protocol"
	"github.com/raghavpillai/mosh-buddy/internal/security"
)

func Register(args []string) error {
	fs := flag.NewFlagSet("_register", flag.ExitOnError)
	session := fs.String("session", "", "session UUID")
	port := fs.Int("port", 0, "tunnel port")
	key := fs.String("key", "", "hex-encoded HMAC key")
	host := fs.String("host", "", "remote hostname for MB_HOST")
	user := fs.String("user", "", "remote username for MB_USER")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Read from stdin to avoid exposure in ps output
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

	if err := protocol.ValidateSessionID(*session); err != nil {
		return fmt.Errorf("invalid session ID: %w", err)
	}

	if _, err := security.KeyFromHex(*key); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

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

	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Printf("server daemon not running, starting automatically...")
		if startErr := autoStartServerDaemon(homeDir, socketPath); startErr != nil {
			return fmt.Errorf("server daemon not running and auto-start failed: %w", startErr)
		}
		conn, err = net.Dial("unix", socketPath)
		if err != nil {
			return fmt.Errorf("connect to server daemon after auto-start: %w", err)
		}
	}
	defer conn.Close()

	msg := &protocol.Message{
		Type:      "register",
		SessionID: *session,
		Port:      *port,
		Key:       *key,
	}
	if err := protocol.Encode(conn, msg); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	resp, err := protocol.Decode(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Type == "error" {
		return fmt.Errorf("registration failed: %s", resp.Error)
	}

	// Write env file so mb works in tmux/new shells without MB_* env vars
	envContent := fmt.Sprintf("MB_SESSION=%s\nMB_PORT=%d\nMB_HOST=%s\nMB_USER=%s\n",
		*session, *port, *host, *user)
	envPath := filepath.Join(homeDir, ".mb", "env")
	_ = os.WriteFile(envPath, []byte(envContent), 0600)

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

	if err := protocol.ValidateSessionID(*session); err != nil {
		return fmt.Errorf("invalid session ID: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	keyDir := filepath.Join(homeDir, ".mb", "sessions", *session)
	os.RemoveAll(keyDir)

	// Clean env file if it belongs to this session
	envPath := filepath.Join(homeDir, ".mb", "env")
	if data, err := os.ReadFile(envPath); err == nil {
		if strings.Contains(string(data), "MB_SESSION="+*session) {
			os.Remove(envPath)
		}
	}

	socketPath := filepath.Join(homeDir, ".mb", "mb.sock")
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		// Daemon may not be running — disk cleanup is enough
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

func autoStartServerDaemon(homeDir, socketPath string) error {
	for _, dir := range []string{
		filepath.Join(homeDir, ".mb"),
		filepath.Join(homeDir, ".mb", "sessions"),
		filepath.Join(homeDir, ".mb", "queue"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	logPath := filepath.Join(homeDir, ".mb", "server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	cmd := exec.Command(exe, "server-daemon")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start server daemon: %w", err)
	}
	logFile.Close()

	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if conn, dialErr := net.Dial("unix", socketPath); dialErr == nil {
			conn.Close()
			log.Printf("server daemon started (pid %d)", cmd.Process.Pid)
			return nil
		}
	}
	return fmt.Errorf("server daemon started but socket not ready after 3s")
}
