package pagination

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

type Cursor struct {
	aead cipher.AEAD
	aad  []byte
}

// Unavailable posts must not leak their IDs or publication times through pagination.
func NewCursor(secret, purpose, scope string) (Cursor, error) {
	key := hmac.New(sha256.New, []byte(secret))
	_, _ = key.Write([]byte(purpose))
	block, err := aes.NewCipher(key.Sum(nil))
	if err != nil {
		return Cursor{}, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Cursor{}, err
	}

	return Cursor{aead: aead, aad: []byte(scope)}, nil
}

func (c Cursor) Encode(id [16]byte, position time.Time) (string, error) {
	var data [28]byte
	copy(data[:16], id[:])
	binary.BigEndian.PutUint64(data[16:24], uint64(position.Unix()))
	binary.BigEndian.PutUint32(data[24:], uint32(position.Nanosecond()))

	return c.encode(data[:])
}

func (c Cursor) EncodeSearch(id [16]byte, rank float32, snapshot int64) (string, error) {
	var data [28]byte
	copy(data[:16], id[:])
	binary.BigEndian.PutUint64(data[16:24], uint64(snapshot))
	binary.BigEndian.PutUint32(data[24:], math.Float32bits(rank))
	return c.encode(data[:])
}

func (c Cursor) encode(data []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(data)+c.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(c.aead.Seal(nonce, nonce, data, c.aad)), nil
}

func (c Cursor) Decode(token string) ([16]byte, time.Time, error) {
	data, err := c.decode(token)
	if err != nil {
		return [16]byte{}, time.Time{}, err
	}

	id := [16]byte(data[:16])
	seconds := int64(binary.BigEndian.Uint64(data[16:24]))
	nanos := binary.BigEndian.Uint32(data[24:])
	if id == [16]byte{} || nanos >= 1_000_000_000 {
		return [16]byte{}, time.Time{}, errors.New("invalid cursor")
	}

	return id, time.Unix(seconds, int64(nanos)).UTC(), nil
}

func (c Cursor) DecodeSearch(token string) ([16]byte, float32, int64, error) {
	data, err := c.decode(token)
	if err != nil {
		return [16]byte{}, 0, 0, err
	}

	id := [16]byte(data[:16])
	snapshot := int64(binary.BigEndian.Uint64(data[16:24]))
	rank := math.Float32frombits(binary.BigEndian.Uint32(data[24:]))
	if id == [16]byte{} || snapshot <= 0 || rank < 0 || math.IsNaN(float64(rank)) || math.IsInf(float64(rank), 0) {
		return [16]byte{}, 0, 0, errors.New("invalid cursor")
	}

	return id, rank, snapshot, nil
}

func (c Cursor) decode(token string) ([]byte, error) {
	const positionSize = 28
	invalid := errors.New("invalid cursor")
	if len(token) != base64.RawURLEncoding.EncodedLen(positionSize+c.aead.NonceSize()+c.aead.Overhead()) {
		return nil, invalid
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return nil, invalid
	}

	nonce, ciphertext := decoded[:c.aead.NonceSize()], decoded[c.aead.NonceSize():]
	data, err := c.aead.Open(nil, nonce, ciphertext, c.aad)
	if err != nil || len(data) != positionSize {
		return nil, invalid
	}

	return data, nil
}
