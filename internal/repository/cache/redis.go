// Package cache provides a Redis-backed cache for rate limiting and token blacklisting.
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache wraps a Redis client.
type Cache struct {
	client *redis.Client
}

// New creates a new Cache connected to the given Redis URL.
func New(ctx context.Context, redisURL string) (*Cache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Cache{client: client}, nil
}

// Ping checks Redis connectivity.
func (c *Cache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the Redis connection.
func (c *Cache) Close() error { return c.client.Close() }

// --- Rate limiting (sliding window counter) ---

// IncrRateLimit increments the request counter for a key within a window.
// Returns the current count and whether this is the first increment (sets TTL).
func (c *Cache) IncrRateLimit(ctx context.Context, key string, window time.Duration) (int64, error) {
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("rate limit incr: %w", err)
	}
	return incr.Val(), nil
}

// --- Token blacklisting ---

// BlacklistToken stores a token ID in Redis until it expires.
func (c *Cache) BlacklistToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	return c.client.Set(ctx, blacklistKey(tokenID), "1", ttl).Err()
}

// IsTokenBlacklisted returns true if the token ID has been blacklisted.
func (c *Cache) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	val, err := c.client.Exists(ctx, blacklistKey(tokenID)).Result()
	if err != nil {
		return false, fmt.Errorf("blacklist check: %w", err)
	}
	return val > 0, nil
}

func blacklistKey(tokenID string) string {
	return "blacklist:" + tokenID
}
