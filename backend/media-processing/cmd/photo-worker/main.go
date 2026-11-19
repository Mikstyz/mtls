package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"mtls/media-processing/internal/imageprep"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "photo processing failed")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("invalid arguments")
	}

	maxEdge, err := strconv.Atoi(os.Args[1])

	if err != nil || maxEdge < 1 || maxEdge > 2048 {
		return fmt.Errorf("invalid preview size")
	}

	input, err := io.ReadAll(io.LimitReader(os.Stdin, imageprep.MaxInputBytes+1))

	if err != nil || len(input) == 0 || len(input) > imageprep.MaxInputBytes {
		return fmt.Errorf("invalid input")
	}

	output, err := imageprep.Prepare(context.Background(), input, maxEdge)

	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(output)
	return err
}
