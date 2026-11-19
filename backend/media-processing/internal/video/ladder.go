package video

import "errors"

type Dimensions struct {
	Width  int
	Height int
}

// Ladder describes additional renditions; the original is always kept separately.
// Rotation must already be derived from trusted media probing.
func Ladder(width, height, rotation int) ([]Dimensions, error) {
	if width < 1 || height < 1 || width > 16384 || height > 16384 || int64(width)*int64(height) > 64_000_000 {
		return nil, errors.New("invalid video dimensions")
	}

	if rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270 {
		return nil, errors.New("unsupported video rotation")
	}

	if rotation == 90 || rotation == 270 {
		width, height = height, width
	}

	short := min(width, height)

	if short < 1080 {
		return nil, nil
	}

	var result []Dimensions

	for _, target := range []int{2160, 1440, 1080, 720} {
		if target >= short {
			continue
		}

		var outWidth, outHeight int

		if width <= height {
			outWidth = target
			outHeight = int(int64(height) * int64(target) / int64(width))
		} else {
			outHeight = target
			outWidth = int(int64(width) * int64(target) / int64(height))
		}

		// Common video codecs require even dimensions.
		outWidth -= outWidth % 2
		outHeight -= outHeight % 2

		if outWidth < 2 || outHeight < 2 || outWidth > width || outHeight > height {
			return nil, errors.New("unsupported video aspect ratio")
		}

		result = append(result, Dimensions{Width: outWidth, Height: outHeight})
	}

	return result, nil
}
