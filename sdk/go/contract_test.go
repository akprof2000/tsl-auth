package tslauth

// Контрактные тесты (docs/client-contract.md §8): векторы из tests/sdk-contract/vectors.json и живые сценарии
// против запущенного TSL Auth. Путь к векторам — SDK_CONTRACT_VECTORS (по умолчанию ../../tests/sdk-contract/vectors.json).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type vectorCase struct {
	Name        string `json:"name"`
	Token       string `json:"token"`
	Expect      string `json:"expect"`
	Now         int64  `json:"now"`
	SkipIfNoNbf bool   `json:"skipIfNoNbf"`
	Issuer      string `json:"issuer"`
}

type vectors struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JwksURI  string `json:"jwksUri"`
	Client   struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"client"`
	Users map[string]struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"users"`
	Expected map[string]struct {
		SubjectType string   `json:"subjectType"`
		Username    string   `json:"username"`
		Subject     string   `json:"subject"`
		Permissions []string `json:"permissions"`
		Roles       []string `json:"roles"`
		ActorSub    string   `json:"actorSub"`
	} `json:"expected"`
	Cases []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	path := os.Getenv("SDK_CONTRACT_VECTORS")
	if path == "" {
		path = filepath.Join("..", "..", "tests", "sdk-contract", "vectors.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vectors.json не найден (%s): %v — сгенерируйте tests/sdk-contract/make-vectors.py", path, err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}
	return &v
}

func (v *vectors) caseToken(t *testing.T, name string) string {
	t.Helper()
	for _, c := range v.Cases {
		if c.Name == name {
			return c.Token
		}
	}
	t.Fatalf("в vectors.json нет случая %s", name)
	return ""
}

// baseOptions — verifier как у обычного API: issuer, audience, ключи через discovery.
func (v *vectors) baseOptions() Options {
	return Options{Issuer: v.Issuer, Audience: v.Audience}
}

func (v *vectors) tokenClient(t *testing.T) *TokenClient {
	t.Helper()
	tc, err := NewTokenClient(Options{Issuer: v.Issuer, ClientID: v.Client.ID, ClientSecret: v.Client.Secret})
	if err != nil {
		t.Fatal(err)
	}
	return tc
}

func payloadOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatal("токен без payload")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestContractVectors — все случаи vectors.json: код ошибки ровно как в expect, для ok_* — поля principal.
func TestContractVectors(t *testing.T) {
	v := loadVectors(t)
	ctx := context.Background()
	shared, err := New(v.baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if c.SkipIfNoNbf {
				if _, has := payloadOf(t, c.Token)["nbf"]; !has {
					t.Skip("в токене нет nbf")
				}
			}
			verifier := shared
			if c.Now != 0 || c.Issuer != "" {
				opts := v.baseOptions()
				opts.JWKSURI = v.JwksURI
				if c.Issuer != "" {
					opts.Issuer = c.Issuer
				}
				if c.Now != 0 {
					now := time.Unix(c.Now, 0)
					opts.Now = func() time.Time { return now }
				}
				if verifier, err = New(opts); err != nil {
					t.Fatal(err)
				}
			}
			p, err := verifier.Verify(ctx, c.Token)
			got := "ok"
			if err != nil {
				got = ErrorCode(err)
				var ae *AuthError
				if !errors.As(err, &ae) {
					t.Fatalf("ошибка не *AuthError: %v", err)
				}
				if !errors.Is(err, &AuthError{Code: got}) {
					t.Errorf("errors.Is по коду не работает: %v", err)
				}
			}
			if got != c.Expect {
				t.Fatalf("expect %s, got %s (%v)", c.Expect, got, err)
			}
			if err != nil {
				return
			}
			exp, ok := v.Expected[c.Name]
			if !ok {
				return
			}
			if exp.SubjectType != "" && p.SubjectType != exp.SubjectType {
				t.Errorf("subjectType: %q != %q", p.SubjectType, exp.SubjectType)
			}
			if exp.Username != "" && p.Username != exp.Username {
				t.Errorf("username: %q != %q", p.Username, exp.Username)
			}
			if exp.Subject != "" && p.Subject != exp.Subject {
				t.Errorf("subject: %q != %q", p.Subject, exp.Subject)
			}
			if exp.Permissions != nil && !reflect.DeepEqual(p.Permissions, exp.Permissions) {
				t.Errorf("permissions: %v != %v", p.Permissions, exp.Permissions)
			}
			if exp.Roles != nil && !reflect.DeepEqual(p.Roles, exp.Roles) {
				t.Errorf("roles: %v != %v", p.Roles, exp.Roles)
			}
			if exp.ActorSub != "" && (p.Actor() == nil || p.Actor().Sub != exp.ActorSub) {
				t.Errorf("actor: %+v, ожидался sub=%s", p.Actor(), exp.ActorSub)
			}
			switch c.Name {
			case "ok_client":
				if p.Username != "" {
					t.Errorf("у сервисного токена username должен отсутствовать: %q", p.Username)
				}
			case "ok_viewer":
				if p.HasPermission("orders.write") {
					t.Error("viewer не должен иметь orders.write")
				}
				if p.HasPermission(v.Audience + ":orders.read") {
					t.Error("полная форма разрешения не должна приниматься")
				}
			case "ok_user":
				if p.Actor() != nil {
					t.Error("у обычного токена actor должен быть nil")
				}
				if p.ExpiresAt.IsZero() || p.Claims["sub"] != p.Subject {
					t.Error("expiresAt/claims заполнены неверно")
				}
			}
		})
	}
}

// TestRefreshRotation — password → refresh: новый refresh отличается и работает; после revoke — invalid_grant.
func TestRefreshRotation(t *testing.T) {
	v := loadVectors(t)
	ctx := context.Background()
	tc := v.tokenClient(t)
	u := v.Users["viewer"]
	first, err := tc.Password(ctx, u.Username, u.Password, "openid", "offline_access", v.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if first.RefreshToken == "" || first.AccessToken == "" || first.ExpiresAt.Before(time.Now()) {
		t.Fatal("password grant вернул неполный TokenSet")
	}
	second, err := tc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh не вернул новый refresh_token (ротация)")
	}
	third, err := tc.Refresh(ctx, second.RefreshToken)
	if err != nil {
		t.Fatalf("новый refresh_token должен работать: %v", err)
	}
	if err := tc.Revoke(ctx, third.RefreshToken); err != nil {
		t.Fatal(err)
	}
	_, err = tc.Refresh(ctx, third.RefreshToken)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "invalid_grant" {
		t.Fatalf("после revoke ожидался TokenError invalid_grant, получено %v", err)
	}
	if te.Status < 400 || te.Status >= 500 {
		t.Errorf("status: %d", te.Status)
	}
}

// TestIntrospectionRevoked — с Introspect=true токен проходит, после revoke(access) — revoked.
func TestIntrospectionRevoked(t *testing.T) {
	v := loadVectors(t)
	ctx := context.Background()
	tc := v.tokenClient(t)
	u := v.Users["operator"]
	ts, err := tc.Password(ctx, u.Username, u.Password, "openid", v.Audience)
	if err != nil {
		t.Fatal(err)
	}
	opts := v.baseOptions()
	opts.Introspect, opts.ClientID, opts.ClientSecret = true, v.Client.ID, v.Client.Secret
	verifier, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, ts.AccessToken); err != nil {
		t.Fatalf("живой токен должен пройти: %v", err)
	}
	intro, err := tc.Introspect(ctx, ts.AccessToken)
	if err != nil || !intro.Active {
		t.Fatalf("introspect active: %+v, %v", intro, err)
	}
	if err := tc.Revoke(ctx, ts.AccessToken); err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(ctx, ts.AccessToken)
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("после revoke ожидался revoked, получено %v", err)
	}
	if intro, err := tc.Introspect(ctx, ts.AccessToken); err != nil || intro.Active {
		t.Fatalf("introspect после revoke: %+v, %v", intro, err)
	}
}

// TestClientCredentialsCache — два вызова подряд дают один токен; после перевода часов на exp — новый.
func TestClientCredentialsCache(t *testing.T) {
	v := loadVectors(t)
	ctx := context.Background()
	now := time.Now()
	tc, err := NewTokenClient(Options{Issuer: v.Issuer, ClientID: v.Client.ID, ClientSecret: v.Client.Secret,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a, err := tc.ClientCredentials(ctx, v.Audience)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tc.ClientCredentials(ctx, v.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if a.AccessToken != b.AccessToken {
		t.Fatal("повторный вызов должен вернуть токен из кэша")
	}
	// Параллельные вызовы при протухшем кэше — один запрос (single-flight): все получают один и тот же токен.
	now = a.ExpiresAt
	results := make(chan string, 8)
	for i := 0; i < 8; i++ {
		go func() {
			ts, err := tc.ClientCredentials(ctx, v.Audience)
			if err != nil {
				results <- "error: " + err.Error()
				return
			}
			results <- ts.AccessToken
		}()
	}
	set := map[string]bool{}
	for i := 0; i < 8; i++ {
		set[<-results] = true
	}
	if len(set) != 1 {
		t.Fatalf("single-flight нарушен: %d разных результатов", len(set))
	}
	for tok := range set {
		if tok == a.AccessToken || strings.HasPrefix(tok, "error:") {
			t.Fatalf("после истечения кэша ожидался новый токен, получено %q", tok[:min(len(tok), 40)])
		}
	}
	// Ошибка запроса кэш не портит: с неверным секретом — TokenError invalid_client.
	bad, _ := NewTokenClient(Options{Issuer: v.Issuer, ClientID: v.Client.ID, ClientSecret: "wrong"})
	_, err = bad.ClientCredentials(ctx, v.Audience)
	var te *TokenError
	if !errors.As(err, &te) || te.Code == "" || te.Status != http.StatusUnauthorized && te.Status != http.StatusBadRequest {
		t.Fatalf("ожидался TokenError 4xx, получено %v", err)
	}
}
