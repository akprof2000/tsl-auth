package tslauth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSet — ответ token_endpoint (контракт §6).
type TokenSet struct {
	AccessToken  string
	RefreshToken string // при ротации — новый; старый больше не использовать
	IDToken      string
	ExpiresAt    time.Time // вычислен из expires_in в момент получения
	Scope        string
	TokenType    string
}

// TokenError — отказ token_endpoint: Code — error из ответа (invalid_grant, invalid_client, …),
// Description — error_description, Status — HTTP-статус. Сеть и 5xx — Code = "unavailable".
type TokenError struct {
	Code        string
	Description string
	Status      int
}

func (e *TokenError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("tslauth: token endpoint: %s (%d): %s", e.Code, e.Status, e.Description)
	}
	return fmt.Sprintf("tslauth: token endpoint: %s (%d)", e.Code, e.Status)
}

// Introspection — ответ introspection_endpoint: Active и все поля ответа в Claims.
type Introspection struct {
	Active bool
	Claims map[string]any
}

// TokenClient получает токены у TSL Auth от имени приложения ClientID/ClientSecret (§6).
// Без секрета, но с ключом (ClientKeyPEM/ClientKeyFile) входит по private_key_jwt: ES256-assertion
// с одноразовым jti, сроком 60 с и aud = issuer сервиса (как в discovery).
// ClientCredentials и ConnectionToken кэшируются до ExpiresAt − 30 с с single-flight; Exchange не кэшируется.
type TokenClient struct {
	opts Options
	ep   *endpoints
	key  *ecdsa.PrivateKey // ключ для private_key_jwt; nil — вход секретом

	mu       sync.Mutex
	cache    map[string]*TokenSet
	inflight map[string]chan struct{}
}

// NewTokenClient создаёт клиент токенов. Обязательны Issuer и ClientID.
func NewTokenClient(opts Options) (*TokenClient, error) {
	opts = opts.withDefaults()
	if opts.Issuer == "" {
		return nil, errors.New("tslauth: не задан Issuer (TSL_AUTH_ISSUER)")
	}
	if opts.ClientID == "" {
		return nil, errors.New("tslauth: не задан ClientID (TSL_AUTH_CLIENT_ID)")
	}
	key, err := loadClientKey(opts)
	if err != nil {
		return nil, err
	}
	return &TokenClient{opts: opts, ep: newEndpoints(opts), key: key, cache: map[string]*TokenSet{}, inflight: map[string]chan struct{}{}}, nil
}

// UsesPrivateKeyJWT — клиент входит по ключу (assertion), а не секретом.
func (c *TokenClient) UsesPrivateKeyJWT() bool { return c.key != nil && c.opts.ClientSecret == "" }

// ConnectionTokenGrantType — обмен токена подключения (PAT, выписанного пользователем этому сервису) на JWT пользователя.
const ConnectionTokenGrantType = "urn:tsl:grant-type:pat"

// ClientCredentials — токен самого сервиса (grant client_credentials) с кэшем по набору scope.
func (c *TokenClient) ClientCredentials(ctx context.Context, scopes ...string) (*TokenSet, error) {
	scope := strings.Join(scopes, " ")
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return c.cached(ctx, scope, form)
}

// ConnectionToken — робот: JWT пользователя по его токену подключения (tslpat_…, выписан в «Мои токены» этому сервису).
// Сервис входит своими учётными данными (секрет или ключ); в JWT — права пользователя и claim act с этим сервисом.
// Кэшируется по токену до ExpiresAt − 30 с, как сервисный токен.
func (c *TokenClient) ConnectionToken(ctx context.Context, connectionToken string) (*TokenSet, error) {
	if connectionToken == "" {
		return nil, errors.New("tslauth: пустой токен подключения")
	}
	form := url.Values{"grant_type": {ConnectionTokenGrantType}, "token": {connectionToken}}
	return c.cached(ctx, "pat:"+connectionToken, form)
}

// cached выполняет grant с кэшем по ключу до ExpiresAt − 30 с; параллельные вызовы с одним ключом делают один запрос.
func (c *TokenClient) cached(ctx context.Context, key string, form url.Values) (*TokenSet, error) {
	scope := key
	for {
		c.mu.Lock()
		if ts, ok := c.cache[scope]; ok && c.opts.now().Before(ts.ExpiresAt.Add(-30*time.Second)) {
			c.mu.Unlock()
			return ts, nil
		}
		if ch, busy := c.inflight[scope]; busy {
			// Запрос уже идёт — ждём его и перечитываем кэш (single-flight).
			c.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, &TokenError{Code: "unavailable", Description: ctx.Err().Error()}
			}
		}
		ch := make(chan struct{})
		c.inflight[scope] = ch
		c.mu.Unlock()

		ts, err := c.grant(ctx, form)

		c.mu.Lock()
		if err == nil {
			c.cache[scope] = ts // ошибка кэш не портит
		}
		delete(c.inflight, scope)
		close(ch)
		c.mu.Unlock()
		return ts, err
	}
}

// Exchange — токен для другого API от имени пользователя (RFC 8693). Не кэшируется.
func (c *TokenClient) Exchange(ctx context.Context, subjectToken string, scopes ...string) (*TokenSet, error) {
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return c.grant(ctx, form)
}

// Refresh обновляет пару токенов; в ответе новый RefreshToken (ротация) — старый больше не использовать.
func (c *TokenClient) Refresh(ctx context.Context, refreshToken string, scopes ...string) (*TokenSet, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return c.grant(ctx, form)
}

// Password — grant password (только серверные приложения).
func (c *TokenClient) Password(ctx context.Context, username, password string, scopes ...string) (*TokenSet, error) {
	form := url.Values{"grant_type": {"password"}, "username": {username}, "password": {password}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return c.grant(ctx, form)
}

// AuthorizationCode обменивает код на токены (PKCE обязателен: codeVerifier).
func (c *TokenClient) AuthorizationCode(ctx context.Context, code, redirectURI, codeVerifier string) (*TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	return c.grant(ctx, form)
}

// Introspect спрашивает introspection_endpoint о токене.
func (c *TokenClient) Introspect(ctx context.Context, token string) (*Introspection, error) {
	doc, err := c.ep.get(ctx)
	if err != nil {
		return nil, &TokenError{Code: "unavailable", Description: err.Error()}
	}
	body, status, err := c.post(ctx, doc.IntrospectionEndpoint, doc.Issuer, url.Values{"token": {token}})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, tokenErrorFrom(status, body)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, &TokenError{Code: "unavailable", Description: "introspection: не JSON", Status: status}
	}
	active, _ := claims["active"].(bool)
	return &Introspection{Active: active, Claims: claims}, nil
}

// Revoke отзывает access- или refresh-токен; успех — 200.
func (c *TokenClient) Revoke(ctx context.Context, token string) error {
	doc, err := c.ep.get(ctx)
	if err != nil {
		return &TokenError{Code: "unavailable", Description: err.Error()}
	}
	body, status, err := c.post(ctx, doc.RevocationEndpoint, doc.Issuer, url.Values{"token": {token}})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return tokenErrorFrom(status, body)
	}
	return nil
}

// grant выполняет запрос к token_endpoint и разбирает TokenSet.
func (c *TokenClient) grant(ctx context.Context, form url.Values) (*TokenSet, error) {
	doc, err := c.ep.get(ctx)
	if err != nil {
		return nil, &TokenError{Code: "unavailable", Description: err.Error()}
	}
	body, status, err := c.post(ctx, doc.TokenEndpoint, doc.Issuer, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, tokenErrorFrom(status, body)
	}
	var res struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.AccessToken == "" {
		return nil, &TokenError{Code: "unavailable", Description: "token endpoint: неожиданный ответ", Status: status}
	}
	return &TokenSet{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		IDToken:      res.IDToken,
		ExpiresAt:    c.opts.now().Add(time.Duration(res.ExpiresIn) * time.Second),
		Scope:        res.Scope,
		TokenType:    res.TokenType,
	}, nil
}

// post отправляет форму с client_id и client_secret (если задан) либо assertion по ключу (aud = issuer из discovery).
// Сетевые ошибки — TokenError unavailable.
func (c *TokenClient) post(ctx context.Context, endpoint, issuer string, form url.Values) ([]byte, int, error) {
	if endpoint == "" {
		return nil, 0, &TokenError{Code: "unavailable", Description: "discovery: адрес endpoint не найден"}
	}
	form.Set("client_id", c.opts.ClientID)
	if c.opts.ClientSecret != "" {
		form.Set("client_secret", c.opts.ClientSecret)
	} else if c.key != nil {
		if issuer == "" {
			issuer = strings.TrimSuffix(c.opts.Issuer, "/") + "/"
		}
		assertion, err := clientAssertion(c.key, c.opts.ClientKeyID, c.opts.ClientID, issuer, c.opts.now())
		if err != nil {
			return nil, 0, &TokenError{Code: "unavailable", Description: err.Error()}
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, &TokenError{Code: "unavailable", Description: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, &TokenError{Code: "unavailable", Description: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, &TokenError{Code: "unavailable", Description: err.Error(), Status: resp.StatusCode}
	}
	return body, resp.StatusCode, nil
}

// tokenErrorFrom строит TokenError из ответа: 4xx с JSON error — как есть, иначе (5xx, не JSON) — unavailable.
func tokenErrorFrom(status int, body []byte) *TokenError {
	if status >= 400 && status < 500 {
		var res struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &res) == nil && res.Error != "" {
			return &TokenError{Code: res.Error, Description: res.Description, Status: status}
		}
	}
	return &TokenError{Code: "unavailable", Description: fmt.Sprintf("HTTP %d", status), Status: status}
}
