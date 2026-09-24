// Демо Go API для TSL Auth (только стандартная библиотека — работает в закрытом контуре).
//
//   - проверяет JWT (RS256) по JWKS сервиса авторизации: подпись, iss, aud, exp;
//   - авторизует по разрешениям из матрицы доступа (claim "permissions" = "client:permission");
//   - вызывает Node API от имени пользователя через token exchange (RFC 8693).
//
// Переменные: AUTH_ISSUER, API_AUDIENCE (demo-go-api), CLIENT_SECRET (для token exchange),
// NODE_API_URL, NODE_API_SCOPE (demo-node-api), PORT, CORS_ORIGIN.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	issuer      = env("AUTH_ISSUER", "http://localhost:8080/")
	audience    = env("API_AUDIENCE", "demo-go-api")
	secret      = env("CLIENT_SECRET", "")
	nodeAPI     = env("NODE_API_URL", "http://localhost:5102")
	nodeScope   = env("NODE_API_SCOPE", "demo-node-api")
	corsOrigin  = env("CORS_ORIGIN", "http://localhost:5102")
	keys        = &jwks{}
	httpClient  = &http.Client{Timeout: 10 * time.Second}
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ---------- JWKS / JWT ----------

// jwks — потокобезопасный кэш открытых ключей подписи (kid → RSA-ключ).
// Ключи перечитываются раз в 10 минут или сразу при встрече неизвестного kid (ротация ключей на сервере).
type jwks struct {
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func (j *jwks) get(kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	k, ok := j.keys[kid]
	stale := time.Since(j.fetched) > 10*time.Minute
	j.mu.RUnlock()
	if ok && !stale {
		return k, nil
	}
	if err := j.refresh(); err != nil { // неизвестный kid — возможно, ротация ключей
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if k, ok = j.keys[kid]; !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return k, nil
}

// refresh находит jwks_uri через OIDC discovery и загружает набор ключей.
// Модуль (n) и экспонента (e) в JWK закодированы base64url big-endian.
func (j *jwks) refresh() error {
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := getJSON(strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return err
	}
	var set struct {
		Keys []struct{ Kid, Kty, N, E string } `json:"keys"`
	}
	if err := getJSON(doc.JwksURI, &set); err != nil {
		return err
	}
	m := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		// Битый ключ пропускается, а не превращается в «пустой» (N=0, E=0): токены с его kid просто не пройдут
		// проверку как с неизвестным ключом, а в журнале будет видна причина.
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			log.Printf("JWKS: ключ %q пропущен — некорректные n/e", k.Kid)
			continue
		}
		m[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	j.mu.Lock()
	j.keys, j.fetched = m, time.Now()
	j.mu.Unlock()
	return nil
}

type claims map[string]any

// strings возвращает claim как список: в JWT одно значение может прийти строкой, а несколько — массивом.
func (c claims) strings(name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// validate локально проверяет access-токен (без обращения к серверу на каждый запрос):
// подпись RS256 по ключу из JWKS, затем iss, aud и exp. Отзыв токена так не виден —
// для мгновенного отзыва нужен introspection (см. демо Python).
func validate(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	// Разрешаем только RS256: защита от подмены алгоритма (alg=none / HS256 с открытым ключом как секретом).
	var header struct{ Alg, Kid string }
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "RS256" {
		return nil, errors.New("unsupported alg")
	}
	key, err := keys.get(header.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	// Подписывается строка "header.payload" в исходном base64url-виде.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("bad signature")
	}
	var c claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, err
	}
	if c["iss"] != issuer {
		return nil, fmt.Errorf("bad issuer %v", c["iss"])
	}
	// aud защищает от использования токена, выданного для другого API.
	if !slices.Contains(c.strings("aud"), audience) {
		return nil, errors.New("token is not for this API (aud)")
	}
	// 30 секунд допуска на расхождение часов (clock skew) между сервером авторизации и API.
	if exp, ok := c["exp"].(float64); !ok || time.Now().Unix() > int64(exp)+30 {
		return nil, errors.New("token expired")
	}
	return c, nil
}

func decodeSegment(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---------- HTTP ----------

type handler func(w http.ResponseWriter, r *http.Request, c claims, token string)

// require проверяет токен и наличие разрешения "<audience>:<permission>" из матрицы доступа.
func require(permission string, next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeJSON(w, 401, map[string]any{"error": "missing bearer token"})
			return
		}
		c, err := validate(token)
		if err != nil {
			writeJSON(w, 401, map[string]any{"error": err.Error()})
			return
		}
		if permission != "" && !slices.Contains(c.strings("permissions"), audience+":"+permission) {
			writeJSON(w, 403, map[string]any{"error": "permission required: " + audience + ":" + permission})
			return
		}
		next(w, r, c, token)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })

	// Любой валидный токен для этого API: кто я и какие у меня права здесь.
	mux.HandleFunc("GET /api/me", require("", func(w http.ResponseWriter, r *http.Request, c claims, _ string) {
		writeJSON(w, 200, map[string]any{
			"service":     "go-api",
			"user":        c["preferred_username"],
			"subjectType": c["subject_type"],
			"permissions": c.strings("permissions"),
			"roles":       c.strings("role"),
		})
	}))

	// Требует разрешения reports.view в матрице demo-go-api.
	mux.HandleFunc("GET /api/reports", require("reports.view", func(w http.ResponseWriter, r *http.Request, c claims, _ string) {
		writeJSON(w, 200, map[string]any{"service": "go-api", "reports": []string{"Выручка за квартал", "Остатки на складе"}, "user": c["preferred_username"]})
	}))

	// Цепочка: обмениваем токен пользователя на токен для Node API и вызываем его от имени пользователя.
	mux.HandleFunc("GET /api/chain", require("reports.view", func(w http.ResponseWriter, r *http.Request, c claims, token string) {
		exchanged, err := exchange(token)
		if err != nil {
			writeJSON(w, 502, map[string]any{"error": "token exchange failed: " + err.Error()})
			return
		}
		req, _ := http.NewRequest("GET", nodeAPI+"/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+exchanged)
		resp, err := httpClient.Do(req)
		if err != nil {
			writeJSON(w, 502, map[string]any{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		var body any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		writeJSON(w, 200, map[string]any{"service": "go-api", "via": "token-exchange", "nodeStatus": resp.StatusCode, "node": body})
	}))

	log.Printf("go-api on :%s (aud=%s, iss=%s)", env("PORT", "5103"), audience, issuer)
	log.Fatal(http.ListenAndServe(":"+env("PORT", "5103"), cors(mux)))
}

// exchange выполняет token exchange (RFC 8693): Go API как confidential client предъявляет
// токен пользователя (subject_token) и получает новый токен с aud = Node API. В новом токене
// сохраняется пользователь, а claim "act" указывает, какой сервис действует от его имени.
func exchange(subjectToken string) (string, error) {
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {audience},
		"client_secret":      {secret},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {nodeScope},
	}
	resp, err := httpClient.PostForm(strings.TrimSuffix(issuer, "/")+"/connect/token", form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%v: %v", body["error"], body["error_description"])
	}
	return body["access_token"].(string), nil
}

// cors разрешает вызовы из браузерного SPA (другой origin); preflight OPTIONS отвечает сразу, без проверки токена.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", corsOrigin)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getJSON(u string, v any) error {
	resp, err := httpClient.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %d %s", u, resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
