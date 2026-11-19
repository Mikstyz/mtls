package imageprep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
)

const (
	MaxInputBytes  = 32 << 20
	maxPixels      = 16_000_000
	maxDimension   = 8192
	MaxOutputBytes = 32 << 20
)

// Prepare creates a metadata-free JPEG or PNG preview from one static image.
// Resource isolation is required around the worker that calls this function.
func Prepare(ctx context.Context, input []byte, maxEdge int) ([]byte, error) {
	if ctx == nil || len(input) == 0 || len(input) > MaxInputBytes || maxEdge < 1 || maxEdge > 2048 {
		return nil, errors.New("invalid image preparation request")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	config, format, err := image.DecodeConfig(bytes.NewReader(input))

	if err != nil || (format != "jpeg" && format != "png") {
		return nil, errors.New("unsupported image")
	}

	if config.Width < 1 || config.Height < 1 || config.Width > maxDimension || config.Height > maxDimension || int64(config.Width)*int64(config.Height) > maxPixels {
		return nil, errors.New("image dimensions exceed limits")
	}

	orientation, err := imageOrientation(input, format)

	if err != nil {
		return nil, fmt.Errorf("invalid image metadata: %w", err)
	}

	source, actualFormat, err := image.Decode(bytes.NewReader(input))

	if err != nil || actualFormat != format || source.Bounds().Dx() != config.Width || source.Bounds().Dy() != config.Height {
		return nil, errors.New("invalid image data")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	oriented := orientedImage{source: source, orientation: orientation}
	bounds := oriented.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	if width > maxEdge || height > maxEdge {
		if width >= height {
			height = max(1, int(int64(height)*int64(maxEdge)/int64(width)))
			width = maxEdge
		} else {
			width = max(1, int(int64(width)*int64(maxEdge)/int64(height)))
			height = maxEdge
		}
	}

	output := image.NewRGBA(image.Rect(0, 0, width, height))

	if err := scale(ctx, output, oriented); err != nil {
		return nil, err
	}

	var encoded bytes.Buffer
	writer := &limitedWriter{ctx: ctx, target: &encoded, remaining: MaxOutputBytes}

	if format == "jpeg" {
		err = jpeg.Encode(writer, output, &jpeg.Options{Quality: 85})
	} else {
		err = png.Encode(writer, output)
	}

	if err != nil {
		return nil, fmt.Errorf("encode image preview: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return encoded.Bytes(), nil
}

type limitedWriter struct {
	ctx       context.Context
	target    *bytes.Buffer
	remaining int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}

	if len(p) > w.remaining {
		return 0, errors.New("image preview exceeds output limit")
	}

	w.remaining -= len(p)
	return w.target.Write(p)
}
