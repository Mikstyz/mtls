package redisshield

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const sessionHintTTL = 5 * time.Minute

var sessionHintScript = redis.NewScript(`
local value = redis.call('GETRANGE', KEYS[1], 0, 36)
if value ~= '' and redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], 300000)
end
return value
`)

// SessionCache stores short-lived lookup hints, never authorization decisions.
type SessionCache struct {
	client           *redis.Client
	key              [32]byte
	unavailableUntil atomic.Int64
	hits             atomic.Uint64
	misses           atomic.Uint64
	failures         atomic.Uint64
}

func (g *Guard) NewSessionCache(secret string) (*SessionCache, error) {
	if len(secret) < 32 {
		return nil, errors.New("session cache key must be at least 32 bytes")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("mtls:auth:session-cache-key:v1"))

	cache := &SessionCache{client: g.client}
	copy(cache.key[:], mac.Sum(nil))

	return cache, nil
}

func (c *SessionCache) cacheKey(tokenHash [32]byte) string {
	mac := hmac.New(sha256.New, c.key[:])
	_, _ = mac.Write(tokenHash[:])

	return "mtls:auth:session-cache:v1:" + hex.EncodeToString(mac.Sum(nil))
}

func (c *SessionCache) Lookup(ctx context.Context, tokenHash [32]byte) (uuid.UUID, bool, error) {
	if err := ctx.Err(); err != nil {
		return uuid.Nil, false, err
	}

	if time.Now().UnixNano() < c.unavailableUntil.Load() {
		c.failures.Add(1)
		return uuid.Nil, false, errors.New("session cache temporarily unavailable")
	}

	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	value, err := sessionHintScript.Run(ctx, c.client, []string{c.cacheKey(tokenHash)}).Text()

	if err == nil && value == "" {
		c.misses.Add(1)
		return uuid.Nil, false, nil
	}

	if err != nil {
		if parent.Err() != nil {
			return uuid.Nil, false, err
		}

		c.failures.Add(1)
		c.unavailableUntil.Store(time.Now().Add(5 * time.Second).UnixNano())
		return uuid.Nil, false, err
	}

	id, err := uuid.Parse(value)

	if err != nil || id == uuid.Nil || id.String() != value {
		c.failures.Add(1)
		return uuid.Nil, false, errors.New("invalid session cache entry")
	}

	c.hits.Add(1)
	return id, true, nil
}

func (c *SessionCache) Remember(ctx context.Context, tokenHash [32]byte, id uuid.UUID) error {
	if id == uuid.Nil {
		return errors.New("invalid session cache identifier")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if time.Now().UnixNano() < c.unavailableUntil.Load() {
		return errors.New("session cache temporarily unavailable")
	}

	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	if err := c.client.Set(ctx, c.cacheKey(tokenHash), id.String(), sessionHintTTL).Err(); err != nil {
		if parent.Err() != nil {
			return err
		}

		c.failures.Add(1)
		c.unavailableUntil.Store(time.Now().Add(5 * time.Second).UnixNano())
		return err
	}

	return nil
}

func (c *SessionCache) Stats() (hits, misses, failures uint64) {
	return c.hits.Load(), c.misses.Load(), c.failures.Load()
}
