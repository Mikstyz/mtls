package recovery

import (
	"encoding/json"
	"errors"
	"os"
)

// WritePrivateReport creates a new, owner-only report without replacing files.
func WritePrivateReport(path string, issue any) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)

	if err != nil {
		return errors.New("cannot create issue file")
	}

	if err := json.NewEncoder(file).Encode(issue); err != nil {
		_ = file.Close()
		return errors.New("cannot write issue file")
	}

	if err := file.Close(); err != nil {
		return errors.New("cannot close issue file")
	}

	return nil
}
