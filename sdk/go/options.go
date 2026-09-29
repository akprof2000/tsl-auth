package tslauth

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Options — настройки Verifier и TokenClient (контракт §1). Нулевые значения заменяются умолчаниями,
// явные значения имеют приоритет над переменными окружения (OptionsFromEnv читает их).
type Options struct {
	Issuer       string // TSL_AUTH_ISSUER — как в iss токена; обязателен
	Audience     string // TSL_AUTH_AUDIENCE — client_id этого API; без него aud не проверяется
	ClientID     string // TSL_AUTH_CLIENT_ID — для клиента токенов и introspection
	ClientSecret string // TSL_AUTH_CLIENT_SECRET
	JWKSURI      string // TSL_AUTH_JWKS_URI — обход discovery (стенды без discovery, тесты)

	ClockSkew      time.Duration // TSL_AUTH_CLOCK_SKEW_SECONDS, по умолчанию 30 с
	JWKSTTL        time.Duration // TSL_AUTH_JWKS_TTL_SECONDS, по умолчанию 600 с
	JWKSMinRefresh time.Duration // TSL_AUTH_JWKS_MIN_REFRESH_SECONDS, по умолчанию 10 с
	HTTPTimeout    time.Duration // TSL_AUTH_HTTP_TIMEOUT_SECONDS, по умолчанию 10 с
	Introspect     bool          // TSL_AUTH_INTROSPECT — после локальной проверки спрашивать introspection

	// Now — часы (nil = time.Now). Подменяется в тестах и при проверке архивных токенов.
	Now func() time.Time
	// HTTPClient — свой транспорт (прокси, корпоративный CA). nil = клиент с таймаутом HTTPTimeout.
	HTTPClient *http.Client
}

// OptionsFromEnv читает настройки из переменных окружения TSL_AUTH_*.
func OptionsFromEnv() Options {
	return Options{
		Issuer:         os.Getenv("TSL_AUTH_ISSUER"),
		Audience:       os.Getenv("TSL_AUTH_AUDIENCE"),
		ClientID:       os.Getenv("TSL_AUTH_CLIENT_ID"),
		ClientSecret:   os.Getenv("TSL_AUTH_CLIENT_SECRET"),
		JWKSURI:        os.Getenv("TSL_AUTH_JWKS_URI"),
		ClockSkew:      envSeconds("TSL_AUTH_CLOCK_SKEW_SECONDS"),
		JWKSTTL:        envSeconds("TSL_AUTH_JWKS_TTL_SECONDS"),
		JWKSMinRefresh: envSeconds("TSL_AUTH_JWKS_MIN_REFRESH_SECONDS"),
		HTTPTimeout:    envSeconds("TSL_AUTH_HTTP_TIMEOUT_SECONDS"),
		Introspect:     envBool("TSL_AUTH_INTROSPECT"),
	}
}

func envSeconds(name string) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return 0
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n * float64(time.Second))
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// withDefaults подставляет умолчания §1 и нормализует issuer.
func (o Options) withDefaults() Options {
	o.Issuer = strings.TrimSpace(o.Issuer)
	if o.ClockSkew == 0 {
		o.ClockSkew = 30 * time.Second
	}
	if o.JWKSTTL == 0 {
		o.JWKSTTL = 600 * time.Second
	}
	if o.JWKSMinRefresh == 0 {
		o.JWKSMinRefresh = 10 * time.Second
	}
	if o.HTTPTimeout == 0 {
		o.HTTPTimeout = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: o.HTTPTimeout}
	}
	return o
}

// now — текущее время по часам из настроек.
func (o Options) now() time.Time { return o.Now() }
