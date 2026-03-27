package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/viper"
)

// Config holds all application configuration loaded from env vars or config file.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Auth     AuthConfig
	Email    EmailConfig
}

type ServerConfig struct {
	Port               int          `mapstructure:"PORT"`
	Environment        string       `mapstructure:"ENVIRONMENT"`         // development | production
	CORSOrigins        string       `mapstructure:"CORS_ORIGINS"`        // comma-separated allowed origins, * for all
	TrustedProxyCIDRs  string       `mapstructure:"TRUSTED_PROXY_CIDRS"` // comma-separated CIDRs or IPs
	TrustedProxyRanges []*net.IPNet `mapstructure:"-"`
}

type DatabaseConfig struct {
	URL             string `mapstructure:"DATABASE_URL"`
	MaxOpenConns    int    `mapstructure:"DB_MAX_OPEN_CONNS"`
	MaxIdleConns    int    `mapstructure:"DB_MAX_IDLE_CONNS"`
	ConnMaxLifetime time.Duration
}

type RedisConfig struct {
	URL string `mapstructure:"REDIS_URL"`
}

type AuthConfig struct {
	JWTSecret            string        `mapstructure:"JWT_SECRET"`
	AccessTokenDuration  time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	RefreshTokenDuration time.Duration `mapstructure:"REFRESH_TOKEN_DURATION"`
	ResetTokenDuration   time.Duration `mapstructure:"RESET_TOKEN_DURATION"`
	RateLimitPerMinute   int           `mapstructure:"RATE_LIMIT_PER_MINUTE"`
}

type EmailConfig struct {
	Host     string `mapstructure:"SMTP_HOST"`
	Port     int    `mapstructure:"SMTP_PORT"`
	Username string `mapstructure:"SMTP_USERNAME"`
	Password string `mapstructure:"SMTP_PASSWORD"`
	From     string `mapstructure:"SMTP_FROM"`
	BaseURL  string `mapstructure:"APP_BASE_URL"` // used in reset email links
}

const minJWTSecretLength = 32

var (
	errInvalidJWTSecret = errors.New("invalid JWT_SECRET: must be non-empty, at least 32 characters, and not use a known placeholder; generate one with: openssl rand -hex 32")

	blockedJWTSecrets = map[string]struct{}{
		"secret":                            {},
		"jwtsecret":                         {},
		"changeme":                          {},
		"yoursecret":                        {},
		"yoursecretminimum32characters":     {},
		"yoursecretminimum32characterslong": {},
		"changemeinproductionusealongrandomstring": {},
	}
)

// Load reads configuration from environment variables (and optionally a .env file).
func Load() (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("PORT", 8080)
	v.SetDefault("ENVIRONMENT", "development")
	v.SetDefault("CORS_ORIGINS", "*")
	v.SetDefault("DB_MAX_OPEN_CONNS", 25)
	v.SetDefault("DB_MAX_IDLE_CONNS", 5)
	v.SetDefault("ACCESS_TOKEN_DURATION", "15m")
	v.SetDefault("REFRESH_TOKEN_DURATION", "168h") // 7 days
	v.SetDefault("RESET_TOKEN_DURATION", "1h")
	v.SetDefault("RATE_LIMIT_PER_MINUTE", 60)
	v.SetDefault("SMTP_PORT", 587)
	v.SetDefault("APP_BASE_URL", "http://localhost:8080")
	v.SetDefault("REDIS_URL", "redis://localhost:6379/0")
	v.SetDefault("TRUSTED_PROXY_CIDRS", "")

	// Load from .env file if present (ignored if missing)
	v.SetConfigFile(".env")
	v.SetConfigType("env")
	_ = v.ReadInConfig()

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	trustedProxyRanges, err := parseTrustedProxyCIDRs(v.GetString("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	cfg.Server = ServerConfig{
		Port:               v.GetInt("PORT"),
		Environment:        v.GetString("ENVIRONMENT"),
		CORSOrigins:        v.GetString("CORS_ORIGINS"),
		TrustedProxyCIDRs:  v.GetString("TRUSTED_PROXY_CIDRS"),
		TrustedProxyRanges: trustedProxyRanges,
	}
	cfg.Database = DatabaseConfig{
		URL:             v.GetString("DATABASE_URL"),
		MaxOpenConns:    v.GetInt("DB_MAX_OPEN_CONNS"),
		MaxIdleConns:    v.GetInt("DB_MAX_IDLE_CONNS"),
		ConnMaxLifetime: 5 * time.Minute,
	}
	cfg.Redis = RedisConfig{
		URL: v.GetString("REDIS_URL"),
	}
	cfg.Auth = AuthConfig{
		JWTSecret:            v.GetString("JWT_SECRET"),
		AccessTokenDuration:  v.GetDuration("ACCESS_TOKEN_DURATION"),
		RefreshTokenDuration: v.GetDuration("REFRESH_TOKEN_DURATION"),
		ResetTokenDuration:   v.GetDuration("RESET_TOKEN_DURATION"),
		RateLimitPerMinute:   v.GetInt("RATE_LIMIT_PER_MINUTE"),
	}
	cfg.Email = EmailConfig{
		Host:     v.GetString("SMTP_HOST"),
		Port:     v.GetInt("SMTP_PORT"),
		Username: v.GetString("SMTP_USERNAME"),
		Password: v.GetString("SMTP_PASSWORD"),
		From:     v.GetString("SMTP_FROM"),
		BaseURL:  v.GetString("APP_BASE_URL"),
	}

	if err := validateJWTSecret(cfg.Auth.JWTSecret); err != nil {
		return nil, err
	}

	return cfg, nil
}

func validateJWTSecret(secret string) error {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return errInvalidJWTSecret
	}

	if len(trimmed) < minJWTSecretLength {
		return errInvalidJWTSecret
	}

	if _, blocked := blockedJWTSecrets[normalizeJWTSecretCandidate(trimmed)]; blocked {
		return errInvalidJWTSecret
	}

	return nil
}

func normalizeJWTSecretCandidate(secret string) string {
	var normalized strings.Builder
	normalized.Grow(len(secret))

	for _, r := range strings.ToLower(secret) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}

	return normalized.String()
}

func parseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	ranges := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}

		if ip := net.ParseIP(candidate); ip != nil {
			ranges = append(ranges, singleIPNet(ip))
			continue
		}

		_, network, err := net.ParseCIDR(candidate)
		if err != nil {
			return nil, fmt.Errorf("parse TRUSTED_PROXY_CIDRS entry %q: %w", candidate, err)
		}
		ranges = append(ranges, network)
	}

	return ranges, nil
}

func singleIPNet(ip net.IP) *net.IPNet {
	if ipv4 := ip.To4(); ipv4 != nil {
		return &net.IPNet{IP: ipv4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

// IsDevelopment returns true when running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// AllowedOrigins parses the comma-separated CORS_ORIGINS value.
func (c *Config) AllowedOrigins() []string {
	if c.Server.CORSOrigins == "*" {
		return []string{"*"}
	}
	parts := strings.Split(c.Server.CORSOrigins, ",")
	origins := make([]string, 0, len(parts))
	for _, o := range parts {
		if s := strings.TrimSpace(o); s != "" {
			origins = append(origins, s)
		}
	}
	return origins
}
