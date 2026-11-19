package credentials

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// LoadPasswordBlocklist must run before the store is used concurrently.
func (s *Store) LoadPasswordBlocklist(path string) error {
	file, err := os.Open(path)

	if err != nil {
		return fmt.Errorf("open password blocklist: %w", err)
	}

	defer file.Close()

	info, err := file.Stat()

	if err != nil {
		return fmt.Errorf("stat password blocklist: %w", err)
	}

	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return errors.New("password blocklist must be a regular file no larger than 64 MiB")
	}

	entries := make(map[[32]byte]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4096)

	for scanner.Scan() {
		password := scanner.Text()

		if password == "" || len(password) > 1024 || !utf8.ValidString(password) {
			return errors.New("password blocklist contains an invalid entry")
		}

		entries[sha256.Sum256([]byte(strings.ToLower(password)))] = struct{}{}
		entries[sha256.Sum256([]byte(strings.ToLower(norm.NFC.String(password))))] = struct{}{}

		if len(entries) > 1000000 {
			return errors.New("password blocklist exceeds one million entries")
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read password blocklist: %w", err)
	}

	if len(entries) == 0 {
		return errors.New("password blocklist is empty")
	}

	s.passwordBlocklist = entries
	return nil
}
