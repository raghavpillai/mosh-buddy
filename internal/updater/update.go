package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

// Update downloads the latest release and replaces the current binary.
func Update(currentVersion string) error {
	fmt.Printf("Current version: %s\n", currentVersion)
	fmt.Println("Checking for updates...")

	client := &http.Client{Timeout: 30 * time.Second}

	// Fetch release info
	resp, err := client.Get(repoAPI)
	if err != nil {
		return fmt.Errorf("fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api: %s", resp.Status)
	}

	var release releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("parse release: %w", err)
	}

	if !isNewer(release.TagName, currentVersion) && currentVersion != "dev" {
		fmt.Printf("Already up to date (%s).\n", currentVersion)
		return nil
	}

	// Find matching asset
	wantName := fmt.Sprintf("mb-%s-%s", runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == wantName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no release binary for %s/%s in %s", runtime.GOOS, runtime.GOARCH, release.TagName)
	}

	// Find current binary path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	fmt.Printf("Downloading %s %s...\n", wantName, release.TagName)

	// Download to temp file in same directory (for atomic rename)
	dir := filepath.Dir(exePath)
	tmpFile, err := os.CreateTemp(dir, "mb-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // clean up on failure

	dlResp, err := client.Get(downloadURL)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("download: %w", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		tmpFile.Close()
		return fmt.Errorf("download: %s", dlResp.Status)
	}

	written, err := io.Copy(tmpFile, dlResp.Body)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("write binary: %w", err)
	}
	tmpFile.Close()

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpPath, exePath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	fmt.Printf("Updated to %s (%d bytes)\n", release.TagName, written)
	fmt.Printf("Binary: %s\n", exePath)

	// Clean up notice file
	homeDir, err := os.UserHomeDir()
	if err == nil {
		os.Remove(filepath.Join(homeDir, ".mb", "update_available"))
	}

	return nil
}
