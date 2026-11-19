package imageprep

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func imageOrientation(data []byte, format string) (int, error) {
	if format == "jpeg" {
		return jpegOrientation(data)
	}
	return pngOrientation(data)
}

func jpegOrientation(data []byte) (int, error) {
	if len(data) < 2 || data[0] != 0xff || data[1] != 0xd8 {
		return 0, errors.New("invalid JPEG header")
	}

	orientation, found := 1, false

	for pos := 2; pos < len(data); {
		if data[pos] != 0xff {
			return 0, errors.New("invalid JPEG marker")
		}
		for pos < len(data) && data[pos] == 0xff {
			pos++
		}
		if pos >= len(data) {
			return 0, errors.New("truncated JPEG marker")
		}
		marker := data[pos]
		pos++

		if marker == 0xda || marker == 0xd9 {
			return orientation, nil
		}
		if marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7) {
			continue
		}
		if pos+2 > len(data) {
			return 0, errors.New("truncated JPEG segment")
		}
		length := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if length < 2 || length > len(data)-pos {
			return 0, errors.New("invalid JPEG segment")
		}
		segment := data[pos+2 : pos+length]
		pos += length

		if marker == 0xe2 && bytes.HasPrefix(segment, []byte{'M', 'P', 'F', 0}) {
			return 0, errors.New("multi-picture JPEG is not supported")
		}
		if marker == 0xe1 && bytes.HasPrefix(segment, []byte{'E', 'x', 'i', 'f', 0, 0}) {
			if found {
				return 0, errors.New("duplicate image metadata")
			}
			found = true
			var err error
			orientation, err = tiffOrientation(segment[6:])
			if err != nil {
				return 0, err
			}
		}
	}
	return 0, errors.New("truncated JPEG")
}

func pngOrientation(data []byte) (int, error) {
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return 0, errors.New("invalid PNG header")
	}

	orientation, found := 1, false
	for pos := 8; pos < len(data); {
		if len(data)-pos < 12 {
			return 0, errors.New("truncated PNG chunk")
		}
		length := uint64(binary.BigEndian.Uint32(data[pos : pos+4]))
		if length > uint64(len(data)-pos-12) {
			return 0, errors.New("invalid PNG chunk")
		}
		name := string(data[pos+4 : pos+8])
		chunk := data[pos+8 : pos+8+int(length)]
		pos += 12 + int(length)
		if name == "acTL" {
			return 0, errors.New("animated PNG is not supported")
		}
		if name == "eXIf" {
			if found {
				return 0, errors.New("duplicate image metadata")
			}
			found = true
			var err error
			orientation, err = tiffOrientation(chunk)
			if err != nil {
				return 0, err
			}
		}
		if name == "IEND" {
			return orientation, nil
		}
	}
	return 0, errors.New("truncated PNG")
}

func tiffOrientation(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, errors.New("truncated TIFF metadata")
	}
	var order binary.ByteOrder
	switch string(data[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 0, errors.New("invalid TIFF byte order")
	}
	if order.Uint16(data[2:4]) != 42 {
		return 0, errors.New("invalid TIFF header")
	}
	offset := uint64(order.Uint32(data[4:8]))
	if offset > uint64(len(data)) || uint64(len(data))-offset < 2 {
		return 0, errors.New("invalid TIFF directory")
	}
	pos := int(offset)
	count := int(order.Uint16(data[pos : pos+2]))
	pos += 2
	if count > 1024 || count > (len(data)-pos)/12 {
		return 0, errors.New("invalid TIFF entries")
	}
	orientation, found := 1, false
	for i := 0; i < count; i++ {
		entry := data[pos+i*12 : pos+(i+1)*12]
		if order.Uint16(entry[0:2]) != 0x0112 {
			continue
		}
		if found || order.Uint16(entry[2:4]) != 3 || order.Uint32(entry[4:8]) != 1 {
			return 0, errors.New("invalid TIFF orientation")
		}
		orientation = int(order.Uint16(entry[8:10]))
		if orientation < 1 || orientation > 8 {
			return 0, errors.New("invalid TIFF orientation")
		}
		found = true
	}
	return orientation, nil
}
