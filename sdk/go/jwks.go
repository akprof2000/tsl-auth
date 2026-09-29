package tslauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// discovery — нужные SDK поля /.well-known/openid-configuration.
type discovery struct {
	Issuer                string `json:"issuer"`
	JwksURI               string `json:"jwks_uri"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// endpoints — кэш discovery на срок JWKSTTL (§1). При JWKSURI в настройках discovery для ключей не нужен.
type endpoints struct {
	opts    Options
	mu      sync.Mutex
	doc     *discovery
	fetched time.Time
}

func newEndpoints(opts Options) *endpoints { return &endpoints{opts: opts} }

// get возвращает discovery-документ, перечитывая его по истечении TTL (старый — если перечитать не удалось).
func (e *endpoints) get(ctx context.Context) (*discovery, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.doc != nil && e.opts.now().Sub(e.fetched) < e.opts.JWKSTTL {
		return e.doc, nil
	}
	var doc discovery
	url := strings.TrimSuffix(e.opts.Issuer, "/") + "/.well-known/openid-configuration"
	if err := getJSON(ctx, e.opts.HTTPClient, url, &doc); err != nil {
		if e.doc != nil {
			return e.doc, nil
		}
		return nil, fmt.Errorf("discovery %s: %w", url, err)
	}
	e.doc, e.fetched = &doc, e.opts.now()
	return e.doc, nil
}

// jwksURI — прямой адрес из настроек либо jwks_uri из discovery.
func (e *endpoints) jwksURI(ctx context.Context) (string, error) {
	if e.opts.JWKSURI != "" {
		return e.opts.JWKSURI, nil
	}
	doc, err := e.get(ctx)
	if err != nil {
		return "", err
	}
	if doc.JwksURI == "" {
		return "", errors.New("discovery: нет jwks_uri")
	}
	return doc.JwksURI, nil
}

// keyCache — кэш открытых ключей подписи (§3): ленивая загрузка, TTL, перечитывание по неизвестному kid
// не чаще minRefresh, single-flight (одно перечитывание на всех ожидающих), пропуск битых ключей.
type keyCache struct {
	fetch      func(ctx context.Context) (map[string]*rsa.PublicKey, error)
	now        func() time.Time
	ttl        time.Duration
	minRefresh time.Duration

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey // nil — ещё не загружались
	fetched     time.Time
	lastAttempt time.Time
	inflight    chan struct{} // не nil, пока идёт перечитывание
}

// get возвращает ключ по kid или ошибку unknown_key.
func (c *keyCache) get(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	now := c.now()
	loaded := c.keys != nil
	stale := loaded && now.Sub(c.fetched) >= c.ttl
	if k, ok := c.keys[kid]; ok && !stale {
		c.mu.Unlock()
		return k, nil
	}
	if ch := c.inflight; ch != nil {
		// Кто-то уже перечитывает — ждём его результат и смотрим ещё раз.
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, authErr(CodeUnknownKey, ctx.Err())
		}
		c.mu.Lock()
		k, ok := c.keys[kid]
		c.mu.Unlock()
		if ok {
			return k, nil
		}
		return nil, ErrUnknownKey
	}
	// Перечитываем, если ключей ещё нет, набор устарел, либо kid неизвестен и лимит частоты позволяет.
	if loaded && !stale && now.Sub(c.lastAttempt) < c.minRefresh {
		c.mu.Unlock()
		return nil, ErrUnknownKey
	}
	ch := make(chan struct{})
	c.inflight, c.lastAttempt = ch, now
	c.mu.Unlock()

	keys, err := c.fetch(ctx)

	c.mu.Lock()
	if err == nil {
		c.keys, c.fetched = keys, c.now()
	} else if c.keys == nil {
		c.keys = map[string]*rsa.PublicKey{} // попытка была: дальше действует лимит частоты
	}
	c.inflight = nil
	close(ch)
	k, ok := c.keys[kid]
	c.mu.Unlock()
	if ok {
		return k, nil
	}
	if err != nil {
		return nil, authErr(CodeUnknownKey, err)
	}
	return nil, ErrUnknownKey
}

// fetchJWKS загружает набор ключей: принимаются только kty=RSA с use отсутствующим или sig;
// ключи с некорректными n/e пропускаются, остальной набор используется.
func fetchJWKS(ctx context.Context, client *http.Client, uri string) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kid, Kty, Use, N, E string
		} `json:"keys"`
	}
	if err := getJSON(ctx, client, uri, &set); err != nil {
		return nil, fmt.Errorf("jwks %s: %w", uri, err)
	}
	m := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || k.Kid == "" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 {
			continue
		}
		m[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	return m, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
