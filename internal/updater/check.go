package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	repoAPI       = "https://api.github.com/repos/raghavpillai/mosh-buddy/releases/latest"
	checkCooldown = 24 * time.Hour
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// CheckInBackground checks for updates in a goroutine. Returns a done channel.
func CheckInBackground(currentVersion, mbDir string) <-chan struct{} {
	done := make(chan struct{})
	if currentVersion == "dev" || mbDir == "" {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		_ = checkForUpdate(currentVersion, mbDir)
	}()
	return done
}

// PrintUpdateNotice prints an update notice if a newer version is available.
func PrintUpdateNotice(currentVersion, mbDir string, done <-chan struct{}) {
	if mbDir == "" {
		return
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}

	noticePath := filepath.Join(mbDir, "update_available")
	data, err := os.ReadFile(noticePath)
	if err != nil {
		return
	}
	newVersion := strings.TrimSpace(string(data))
	if newVersion == "" || newVersion == currentVersion {
		os.Remove(noticePath)
		return
	}
	fmt.Fprintf(os.Stderr, "\nmb %s available (you have %s). Run \"mb update\" to upgrade.\n", newVersion, currentVersion)
}

func checkForUpdate(currentVersion, mbDir string) error {
	checkFile := filepath.Join(mbDir, "last_update_check")
	if info, err := os.Stat(checkFile); err == nil {
		if time.Since(info.ModTime()) < checkCooldown {
			return nil
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(repoAPI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api: %s", resp.Status)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return err
	}

	_ = os.MkdirAll(mbDir, 0700)
	_ = os.WriteFile(checkFile, []byte(time.Now().Format(time.RFC3339)), 0600)

	if isNewer(release.TagName, currentVersion) {
		noticePath := filepath.Join(mbDir, "update_available")
		_ = os.WriteFile(noticePath, []byte(release.TagName), 0600)
	} else {
		os.Remove(filepath.Join(mbDir, "update_available"))
	}

	return nil
}

// isNewer compares semver tags like "v1.2.3".
func isNewer(remote, current string) bool {
	r := parseVersion(remote)
	c := parseVersion(current)
	if r == nil || c == nil {
		return remote != current
	}
	for i := 0; i < 3; i++ {
		if r[i] > c[i] {
			return true
		}
		if r[i] < c[i] {
			return false
		}
	}
	return false
}

func parseVersion(s string) []int {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		nums[i] = n
	}
	return nums
}
