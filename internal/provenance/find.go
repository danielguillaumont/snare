// Package provenance names the file a gateway input fingerprint came from
// (docs/M9-provenance.md §3). It runs where the documents are and sends nothing anywhere.
package provenance

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danielguillaumont/snare/internal/gateway"
)

var fingerprintShape = regexp.MustCompile(`^[0-9a-f]{16}$`)

// MaxFile: larger files are skipped. A tool result that size is unlikely, and hashing a
// disk image to find a ticket is not worth the wait.
const MaxFile = 32 << 20

// Match is a file whose text has the fingerprint.
type Match struct {
	Path string
	// LF: the file has CRLF line ends, and matches once they are read as LF.
	LF bool
}

// Find hashes every regular file under dirs, as-is and with CRLF turned into LF, and
// returns those whose gateway fingerprint is hash, with the number of files hashed. It
// skips .git directories and does not follow symlinks.
func Find(hash string, dirs []string) ([]Match, int, error) {
	if !fingerprintShape.MatchString(hash) {
		return nil, 0, errors.New("-hash must be the 16-hex-character fingerprint from the alert")
	}
	var out []Match
	scanned := 0
	for _, root := range dirs {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if info, err := d.Info(); err != nil || info.Size() > MaxFile {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil // unreadable: a tool could not have returned it either
			}
			scanned++
			text := string(b)
			switch {
			case gateway.InputFingerprint(text) == hash:
				out = append(out, Match{Path: p})
			case strings.Contains(text, "\r\n") && gateway.InputFingerprint(strings.ReplaceAll(text, "\r\n", "\n")) == hash:
				out = append(out, Match{Path: p, LF: true})
			}
			return nil
		})
		if err != nil {
			return nil, scanned, err
		}
	}
	return out, scanned, nil
}
