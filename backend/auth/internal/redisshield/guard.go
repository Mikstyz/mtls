package redisshield

import (
	"context"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

var counterScript = redis.NewScript(`
local current = redis.call('GET', KEYS[1])
if current and redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], 60000)
end
if current and tonumber(current) >= tonumber(ARGV[1]) then
    return 0
end
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('PEXPIRE', KEYS[1], 60000)
end
return 1
`)

type Guard struct {
	client           *redis.Client
	unavailableUntil atomic.Int64
	fallbacks        atomic.Uint64
	blocked          atomic.Uint64
}

func New(client *redis.Client) *Guard {
	return &Guard{client: client}
}

// Allow is an optional coarse shield; an error must fall back to PostgreSQL.
func (g *Guard) Allow(ctx context.Context, hashedKey []byte, limit int) (bool, error) {
	if len(hashedKey) != 32 || limit < 1 {
		g.fallbacks.Add(1)
		return true, errors.New("invalid rate guard input")
	}

	if err := ctx.Err(); err != nil {
		return true, err
	}

	if time.Now().UnixNano() < g.unavailableUntil.Load() {
		g.fallbacks.Add(1)
		return true, errors.New("redis rate guard temporarily unavailable")
	}

	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()

	key := "mtls:auth:ip-guard:v1:" + hex.EncodeToString(hashedKey)
	result, err := counterScript.Run(ctx, g.client, []string{key}, limit).Int64()

	if err != nil {
		if parent.Err() != nil {
			return true, err
		}

		g.fallbacks.Add(1)
		g.unavailableUntil.Store(time.Now().Add(5 * time.Second).UnixNano())
		return true, err
	}

	switch result {
	case 0:
		g.blocked.Add(1)
		return false, nil
	case 1:
		return true, nil
	default:
		g.fallbacks.Add(1)
		return true, errors.New("invalid redis rate guard response")
	}
}

func (g *Guard) Stats() (blocked, fallbacks uint64) {
	return g.blocked.Load(), g.fallbacks.Load()
}
