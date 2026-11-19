package video

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

const MaxProbeOutput = 32 << 10

type ProbeLimits struct {
	Duration time.Duration
	Pixels   int64
	FPS      int
}

type Source struct {
	Duration   time.Duration
	VideoCodec string
	AudioCodec string
	Dimensions Dimensions
	Rotation   int
	FrameRate  float64
	Renditions []Dimensions
}

type probeStream struct {
	Type             string `json:"codec_type"`
	Codec            string `json:"codec_name"`
	Width            int    `json:"width"`
	Height           int    `json:"height"`
	AspectRatio      string `json:"sample_aspect_ratio"`
	AverageFrameRate string `json:"avg_frame_rate"`
	NominalFrameRate string `json:"r_frame_rate"`
	Disposition      struct {
		AttachedPicture int `json:"attached_pic"`
	} `json:"disposition"`
	SideData []struct {
		Rotation *int `json:"rotation"`
	} `json:"side_data_list"`
}

// ParseMP4Probe reads metadata emitted by the worker's bounded ffprobe run.
// It accepts one video track and at most one audio track.
func ParseMP4Probe(data []byte, limits ProbeLimits) (Source, error) {
	if len(data) == 0 || len(data) > MaxProbeOutput || limits.Duration <= 0 ||
		limits.Duration > 24*time.Hour || limits.Pixels < 1 || limits.Pixels > 64_000_000 ||
		limits.FPS < 1 || limits.FPS > 240 {
		return Source{}, errors.New("invalid video probe limits or output")
	}

	var result struct {
		Streams []probeStream `json:"streams"`
		Format  struct {
			Name     string `json:"format_name"`
			Duration string `json:"duration"`
			Tags     struct {
				Brand string `json:"major_brand"`
			} `json:"tags"`
		} `json:"format"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF ||
		result.Format.Name != "mov,mp4,m4a,3gp,3g2,mj2" || !mp4Brand(result.Format.Tags.Brand) ||
		len(result.Streams) < 1 || len(result.Streams) > 2 {
		return Source{}, errors.New("unsupported MP4 container or tracks")
	}

	seconds, err := strconv.ParseFloat(result.Format.Duration, 64)

	if err != nil || math.IsNaN(seconds) || seconds <= 0 || seconds > limits.Duration.Seconds() {
		return Source{}, errors.New("video duration outside limits")
	}

	source := Source{Duration: time.Duration(seconds * float64(time.Second))}
	if source.Duration == 0 {
		return Source{}, errors.New("invalid video duration")
	}

	for _, stream := range result.Streams {
		switch stream.Type {
		case "audio":
			if source.AudioCodec != "" || (stream.Codec != "aac" && stream.Codec != "mp3") {
				return Source{}, errors.New("unsupported MP4 audio track")
			}
			source.AudioCodec = stream.Codec
		case "video":
			if source.VideoCodec != "" {
				return Source{}, errors.New("multiple MP4 video tracks")
			}
			if err := setVideoTrack(&source, stream, limits); err != nil {
				return Source{}, err
			}
		default:
			return Source{}, errors.New("unexpected MP4 track")
		}
	}

	if source.VideoCodec == "" {
		return Source{}, errors.New("MP4 video track is missing")
	}

	return source, nil
}

func mp4Brand(brand string) bool {
	switch brand {
	case "isom", "iso2", "iso3", "iso4", "iso5", "iso6", "iso7", "iso8", "iso9", "mp41", "mp42", "avc1", "dash", "M4V ":
		return true
	default:
		return false
	}
}

func setVideoTrack(source *Source, stream probeStream, limits ProbeLimits) error {
	switch stream.Codec {
	case "h264", "hevc", "av1", "vp9":
	default:
		return errors.New("unsupported MP4 video codec")
	}

	if stream.Disposition.AttachedPicture != 0 || (stream.AspectRatio != "" && stream.AspectRatio != "N/A" && stream.AspectRatio != "1:1") ||
		stream.Width < 2 || stream.Height < 2 || stream.Width > 16384 || stream.Height > 16384 ||
		int64(stream.Width)*int64(stream.Height) > limits.Pixels {
		return errors.New("unsupported MP4 video dimensions")
	}

	average, ok := boundedFrameRate(stream.AverageFrameRate, limits.FPS)
	if !ok {
		return errors.New("average frame rate outside limits")
	}
	if _, ok := boundedFrameRate(stream.NominalFrameRate, limits.FPS); !ok {
		return errors.New("nominal frame rate outside limits")
	}

	rotation := 0
	seenRotation := false
	for _, side := range stream.SideData {
		if side.Rotation == nil {
			continue
		}
		if seenRotation || *side.Rotation < -270 || *side.Rotation > 270 || *side.Rotation%90 != 0 {
			return errors.New("unsupported MP4 video rotation")
		}
		seenRotation = true
		rotation = (*side.Rotation + 360) % 360
	}

	renditions, err := Ladder(stream.Width, stream.Height, rotation)
	if err != nil {
		return err
	}

	source.VideoCodec = stream.Codec
	source.Dimensions = Dimensions{Width: stream.Width, Height: stream.Height}
	source.Rotation = rotation
	source.FrameRate = average
	source.Renditions = renditions
	return nil
}

func boundedFrameRate(value string, limit int) (float64, bool) {
	n, d, ok := strings.Cut(value, "/")
	if !ok {
		return 0, false
	}
	numerator, nErr := strconv.ParseUint(n, 10, 32)
	denominator, dErr := strconv.ParseUint(d, 10, 32)
	if nErr != nil || dErr != nil || numerator == 0 || denominator == 0 || numerator > uint64(limit)*denominator {
		return 0, false
	}
	return float64(numerator) / float64(denominator), true
}
