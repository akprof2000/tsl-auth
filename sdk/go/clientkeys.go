package tslauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Ключи клиента для входа по ключу (private_key_jwt, контракт §6): закрытый ключ EC P-256 в PEM остаётся
// у клиента и только подписывает assertion; открытая часть (JWK) регистрируется у сервиса
// (POST /api/app/clients), kid — отпечаток RFC 7638.

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// GenerateClientKeyPEM создаёт закрытый ключ EC P-256 (PKCS#8 PEM).
func GenerateClientKeyPEM() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParseClientKeyPEM читает ключ из PEM (PKCS#8 «PRIVATE KEY» или SEC1 «EC PRIVATE KEY»); кривая должна быть P-256.
func ParseClientKeyPEM(pemText string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, errors.New("tslauth: ключ клиента: не PEM")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tslauth: ключ клиента: %w", err)
		}
		key = k
	default:
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tslauth: ключ клиента: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("tslauth: ключ клиента должен быть EC P-256 (ES256)")
		}
		key = ec
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("tslauth: ключ клиента должен быть EC P-256 (ES256)")
	}
	return key, nil
}

// PublicJWK — открытая часть ключа как JWK с kid (отпечаток RFC 7638).
func PublicJWK(key *ecdsa.PrivateKey) map[string]string {
	x, y := coordinates(key)
	return map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": thumbprint(x, y), "alg": "ES256", "use": "sig"}
}

// PublicJWKS — JWKS с одним ключом: тело поля jwks при регистрации подчинённого клиента.
func PublicJWKS(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{"keys": []map[string]string{PublicJWK(key)}}
}

// KeyID — отпечаток RFC 7638 ключа (тот же kid присваивает сервис).
func KeyID(key *ecdsa.PrivateKey) string {
	x, y := coordinates(key)
	return thumbprint(x, y)
}

func coordinates(key *ecdsa.PrivateKey) (string, string) {
	size := (key.Curve.Params().BitSize + 7) / 8
	return b64url(key.X.FillBytes(make([]byte, size))), b64url(key.Y.FillBytes(make([]byte, size)))
}

func thumbprint(x, y string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)))
	return b64url(sum[:])
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientAssertion подписывает assertion RFC 7523: ES256, typ client-authentication+jwt, iss=sub=client_id,
// aud — issuer сервиса (как в discovery), одноразовый jti, срок 60 секунд.
func clientAssertion(key *ecdsa.PrivateKey, kid, clientID, audience string, now time.Time) (string, error) {
	if kid == "" {
		kid = KeyID(key)
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "client-authentication+jwt", "kid": kid})
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	payload, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": audience, "jti": fmt.Sprintf("%x", jti),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
	})
	input := b64url(header) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS ES256 — «сырая» подпись r||s по 32 байта, не DER.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64url(sig), nil
}

// loadClientKey читает ключ из Options (PEM строкой или файлом); nil — ключ не задан.
func loadClientKey(o Options) (*ecdsa.PrivateKey, error) {
	text := o.ClientKeyPEM
	if text == "" && o.ClientKeyFile != "" {
		raw, err := os.ReadFile(o.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("tslauth: файл ключа клиента: %w", err)
		}
		text = string(raw)
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	return ParseClientKeyPEM(text)
}
