package lifecycle

import (
	"context"

	"github.com/google/uuid"
)

func (s *Store) CheckVideoInput(ctx context.Context, id, lease uuid.UUID, original Variant) error {
	if original.Name != "original.mp4" {
		return ErrInvalid
	}
	return s.checkInput(ctx, id, lease, "video", original.Size, original.SHA256, 1<<40)
}

// The worker derives the rendition set from the probed original.
func (s *Store) MarkVideoProcessed(ctx context.Context, id, lease uuid.UUID, durationMillis int64, variants []Variant) error {
	if durationMillis < 1 || durationMillis > 86400000 || len(variants) < 2 || len(variants) > 13 {
		return ErrInvalid
	}

	seen := make(map[string]bool, len(variants))
	for _, v := range variants {
		switch v.Name {
		case "poster.jpg", "poster-25.jpg", "poster-60.jpg":
			if v.Size > 1<<20 {
				return ErrInvalid
			}
		case "original.mp4", "720p.mp4", "1080p.mp4", "1440p.mp4", "2160p.mp4":
		case "adaptive.m3u8", "720p.m3u8", "1080p.m3u8", "1440p.m3u8", "2160p.m3u8":
			if v.Size > 2<<20 {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		if v.Size <= 0 || v.Size > 1<<40 || seen[v.Name] {
			return ErrInvalid
		}
		seen[v.Name] = true
	}
	if !seen["poster.jpg"] {
		return ErrInvalid
	}

	hasRenditions := false
	for _, rendition := range []string{"720p", "1080p", "1440p", "2160p"} {
		if seen[rendition+".mp4"] != seen[rendition+".m3u8"] {
			return ErrInvalid
		}
		hasRenditions = hasRenditions || seen[rendition+".mp4"]
	}
	if seen["adaptive.m3u8"] != hasRenditions {
		return ErrInvalid
	}

	if err := s.CheckVideoInput(ctx, id, lease, variants[0]); err != nil {
		return err
	}
	return s.markProcessed(ctx, id, lease, "video", &durationMillis, variants)
}
