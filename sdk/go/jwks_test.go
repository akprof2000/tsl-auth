package tslauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestJWKSRotation — заглушка JWKS: сначала пустой набор, затем настоящий. Первая проверка — unknown_key,
// повторная сразу — тоже unknown_key без обращения (лимит частоты), после JWKSMinRefresh — ok.
func TestJWKSRotation(t *testing.T) {
	v := loadVectors(t)
	realKeys, err := http.Get(v.JwksURI)
	if err != nil {
		t.Fatal(err)
	}
	realBody, _ := io.ReadAll(realKeys.Body)
	realKeys.Body.Close()

	var hits atomic.Int32
	var rotated atomic.Bool
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if rotated.Load() {
			_, _ = w.Write(realBody)
			return
		}
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer stub.Close()

	verifier, err := New(Options{Issuer: v.Issuer, Audience: v.Audience, JWKSURI: stub.URL, JWKSMinRefresh: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token := v.caseToken(t, "ok_user")

	if _, err := verifier.Verify(ctx, token); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("пустой JWKS: ожидался unknown_key, получено %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("обращений к JWKS: %d, ожидалось 1", hits.Load())
	}
	rotated.Store(true)
	if _, err := verifier.Verify(ctx, token); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("до истечения JWKSMinRefresh ожидался unknown_key, получено %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("лимит частоты нарушен: обращений %d", hits.Load())
	}
	time.Sleep(1100 * time.Millisecond)
	p, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("после ротации ожидался ok, получено %v", err)
	}
	if hits.Load() != 2 || p.Username == "" {
		t.Fatalf("обращений %d (ожидалось 2), username %q", hits.Load(), p.Username)
	}
	// Ключ в кэше — новых обращений нет.
	if _, err := verifier.Verify(ctx, token); err != nil || hits.Load() != 2 {
		t.Fatalf("кэш ключей: err=%v, обращений %d", err, hits.Load())
	}
}

// TestJWKSSingleFlight — параллельные первые проверки делают одну загрузку JWKS.
func TestJWKSSingleFlight(t *testing.T) {
	v := loadVectors(t)
	realKeys, err := http.Get(v.JwksURI)
	if err != nil {
		t.Fatal(err)
	}
	realBody, _ := io.ReadAll(realKeys.Body)
	realKeys.Body.Close()

	var hits atomic.Int32
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write(realBody)
	}))
	defer stub.Close()
	verifier, _ := New(Options{Issuer: v.Issuer, Audience: v.Audience, JWKSURI: stub.URL})
	token := v.caseToken(t, "ok_user")

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := verifier.Verify(context.Background(), token)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("single-flight нарушен: загрузок %d", hits.Load())
	}
}

// TestJWKSSkipsBrokenKeys — ключ с некорректным n/e и ключ use=enc пропускаются, остальной набор работает.
func TestJWKSSkipsBrokenKeys(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"kty": "RSA", "kid": "good", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())}
	set := map[string]any{"keys": []any{
		map[string]any{"kty": "RSA", "kid": "broken", "n": "!!!", "e": "AQAB"},
		map[string]any{"kty": "RSA", "kid": "empty", "n": "", "e": ""},
		map[string]any{"kty": "RSA", "kid": "enc", "use": "enc", "n": good["n"], "e": good["e"]},
		map[string]any{"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
		good,
	}}
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer stub.Close()
	keys, err := fetchJWKS(context.Background(), http.DefaultClient, stub.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys["good"] == nil || keys["good"].N.Cmp(priv.N) != 0 {
		t.Fatalf("ожидался единственный ключ good, получено %d", len(keys))
	}
}

// TestJWKSNetworkErrorKeepsOldKeys — при недоступном JWKS после истечения TTL используется старый набор.
func TestJWKSNetworkErrorKeepsOldKeys(t *testing.T) {
	v := loadVectors(t)
	realKeys, err := http.Get(v.JwksURI)
	if err != nil {
		t.Fatal(err)
	}
	realBody, _ := io.ReadAll(realKeys.Body)
	realKeys.Body.Close()

	var down atomic.Bool
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(realBody)
	}))
	defer stub.Close()
	now := time.Now()
	verifier, _ := New(Options{Issuer: v.Issuer, Audience: v.Audience, JWKSURI: stub.URL, JWKSTTL: time.Minute,
		Now: func() time.Time { return now }})
	token := v.caseToken(t, "ok_user")
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	now = now.Add(2 * time.Minute) // TTL истёк, сеть недоступна — старый набор продолжает работать
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("сетевая ошибка не должна ронять проверку: %v", err)
	}
}
