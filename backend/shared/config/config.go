package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/pelletier/go-toml/v2"
)

const maxConfigSize = 1 << 20

// Load reads a component's configuration from the specified file.
func Load(path string, target any) error {
	if target == nil {
		return fmt.Errorf("config target is required")
	}

	file, err := os.Open(path)

	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}

	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))

	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if len(data) > maxConfigSize {
		return fmt.Errorf("config exceeds %d bytes", maxConfigSize)
	}

	decoder := toml.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	return nil
}
