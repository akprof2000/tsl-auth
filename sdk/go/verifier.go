package tslauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Verifier проверяет access-токены TSL Auth по контракту §2–§3. Безопасен для параллельного использования.
type Verifier struct {
	opts Options
	ep   *endpoints
	keys *keyCache
}

// New создаёт Verifier. Обязателен Options.Issuer; Audience нужен любому API (без него aud не проверяется).
func New(opts Options) (*Verifier, error) {
	opts = opts.withDefaults()
	if opts.Issuer == "" {
		return nil, errors.New("tslauth: не задан Issuer (TSL_AUTH_ISSUER)")
	}
	if opts.Introspect && opts.ClientID == "" {
		return nil, errors.New("tslauth: для Introspect нужен ClientID (TSL_AUTH_CLIENT_ID)")
	}
	v := &Verifier{opts: opts, ep: newEndpoints(opts)}
	v.keys = &keyCache{
		now:        opts.Now,
		ttl:        opts.JWKSTTL,
		minRefresh: opts.JWKSMinRefresh,
		fetch: func(ctx context.Context) (map[string]*rsa.PublicKey, error) {
			uri, err := v.ep.jwksURI(ctx)
			if err != nil {
				return nil, err
			}
			return fetchJWKS(ctx, opts.HTTPClient, uri)
		},
	}
	return v, nil
}

// Options — действующие настройки (с умолчаниями).
func (v *Verifier) Options() Options { return v.opts }

// Verify проверяет токен в порядке §2 и возвращает principal. Ошибка — *AuthError с кодом §2.
func (v *Verifier) Verify(ctx context.Context, token string) (*Principal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrMalformed
	}
	// 2. Три части; заголовок и payload — JSON в base64url.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, ErrMalformed
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil || claims == nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	// 3. Только RS256 — до любых обращений к ключам.
	if header.Alg != "RS256" {
		return nil, ErrUnsupportedAlg
	}
	// 4. kid обязателен.
	if header.Kid == "" {
		return nil, ErrMalformed
	}
	// 5. Ключ из кэша JWKS.
	key, err := v.keys.get(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	// 6. Подпись — до чтения claims.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, ErrBadSignature
	}
	// 7. iss (без завершающего "/").
	if strings.TrimSuffix(str(claims["iss"]), "/") != strings.TrimSuffix(v.opts.Issuer, "/") {
		return nil, ErrBadIssuer
	}
	// 8. exp обязателен; nbf — если есть.
	now := v.opts.now().Unix()
	skew := int64(v.opts.ClockSkew.Seconds())
	exp, ok := numClaim(claims["exp"])
	if !ok || now > exp+skew {
		return nil, ErrExpired
	}
	if nbf, ok := numClaim(claims["nbf"]); ok && now < nbf-skew {
		return nil, ErrNotYetValid
	}
	// 9. aud содержит audience.
	if v.opts.Audience != "" && !contains(stringList(claims["aud"]), v.opts.Audience) {
		return nil, ErrBadAudience
	}
	// 10. Introspection — мгновенный отзыв.
	if v.opts.Introspect {
		if err := v.introspect(ctx, token); err != nil {
			return nil, err
		}
	}
	return newPrincipal(claims, v.opts.Audience), nil
}

// introspect спрашивает introspection_endpoint: active=false → revoked; сеть или не-200 → introspection_unavailable.
func (v *Verifier) introspect(ctx context.Context, token string) error {
	doc, err := v.ep.get(ctx)
	if err != nil {
		return authErr(CodeIntrospectionUnavailable, err)
	}
	if doc.IntrospectionEndpoint == "" {
		return authErr(CodeIntrospectionUnavailable, errors.New("discovery: нет introspection_endpoint"))
	}
	form := url.Values{"token": {token}, "client_id": {v.opts.ClientID}}
	if v.opts.ClientSecret != "" {
		form.Set("client_secret", v.opts.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return authErr(CodeIntrospectionUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := v.opts.HTTPClient.Do(req)
	if err != nil {
		return authErr(CodeIntrospectionUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return authErr(CodeIntrospectionUnavailable, fmt.Errorf("introspection: HTTP %d", resp.StatusCode))
	}
	var res struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return authErr(CodeIntrospectionUnavailable, err)
	}
	if !res.Active {
		return ErrRevoked
	}
	return nil
}

func decodeSegment(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
