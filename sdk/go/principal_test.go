package tslauth

import (
	"os"
	"reflect"
	"testing"
	"time"
)

// TestPrincipalNormalization — правила §4: строка/массив, префикс audience, actor, scopes, amr.
func TestPrincipalNormalization(t *testing.T) {
	claims := map[string]any{
		"sub": "u1", "subject_type": "user", "preferred_username": "ivan", "name": "Иван", "email": "ivan@corp",
		"role":        "orders-api:manager",
		"permissions": []any{"orders-api:orders.read", "billing:pay", "orders-api:", 42},
		"scope":       "openid orders-api",
		"amr":         []any{"pwd", "otp", "mfa"},
		"act":         map[string]any{"sub": "gateway", "act": map[string]any{"sub": "spa"}},
		"exp":         float64(1_800_000_000),
		"aud":         "orders-api",
	}
	p := newPrincipal(claims, "orders-api")
	if p.Subject != "u1" || p.SubjectType != "user" || p.Username != "ivan" || p.Name != "Иван" || p.Email != "ivan@corp" {
		t.Fatalf("базовые поля: %+v", p)
	}
	if !reflect.DeepEqual(p.Roles, []string{"manager"}) || !reflect.DeepEqual(p.AllRoles, []string{"orders-api:manager"}) {
		t.Fatalf("roles: %v / %v", p.Roles, p.AllRoles)
	}
	if !reflect.DeepEqual(p.Permissions, []string{"orders.read"}) || len(p.AllPermissions) != 3 {
		t.Fatalf("permissions: %v / %v", p.Permissions, p.AllPermissions)
	}
	if !p.HasPermission("orders.read") || p.HasPermission("orders-api:orders.read") || p.HasPermission("pay") {
		t.Fatal("HasPermission")
	}
	if !p.HasRole("manager") || p.HasRole("orders-api:manager") {
		t.Fatal("HasRole")
	}
	if !p.IsMFA() || !reflect.DeepEqual(p.Scopes, []string{"openid", "orders-api"}) {
		t.Fatal("IsMFA/Scopes")
	}
	if a := p.Actor(); a == nil || a.Sub != "gateway" || a.Act == nil || a.Act.Sub != "spa" || a.Act.Act != nil {
		t.Fatalf("actor: %+v", a)
	}
	if !p.ExpiresAt.Equal(time.Unix(1_800_000_000, 0)) || p.Claims["aud"] != "orders-api" {
		t.Fatal("expiresAt/claims")
	}

	empty := newPrincipal(map[string]any{"sub": "c1", "subject_type": "client"}, "orders-api")
	if empty.Roles == nil || len(empty.Roles) != 0 || len(empty.Permissions) != 0 || len(empty.Amr) != 0 ||
		empty.IsMFA() || empty.Actor() != nil || empty.Username != "" || len(empty.Scopes) != 0 {
		t.Fatalf("отсутствующие claims → пустые списки: %+v", empty)
	}
}

func TestOptionsFromEnv(t *testing.T) {
	t.Setenv("TSL_AUTH_ISSUER", "https://auth.corp/")
	t.Setenv("TSL_AUTH_AUDIENCE", "orders-api")
	t.Setenv("TSL_AUTH_CLIENT_ID", "orders-api")
	t.Setenv("TSL_AUTH_CLIENT_SECRET", "s")
	t.Setenv("TSL_AUTH_JWKS_URI", "https://auth.corp/.well-known/jwks")
	t.Setenv("TSL_AUTH_CLOCK_SKEW_SECONDS", "5")
	t.Setenv("TSL_AUTH_JWKS_TTL_SECONDS", "120")
	t.Setenv("TSL_AUTH_JWKS_MIN_REFRESH_SECONDS", "1")
	t.Setenv("TSL_AUTH_HTTP_TIMEOUT_SECONDS", "3")
	t.Setenv("TSL_AUTH_INTROSPECT", "true")
	o := OptionsFromEnv()
	if o.Issuer != "https://auth.corp/" || o.Audience != "orders-api" || o.ClientID != "orders-api" || o.ClientSecret != "s" ||
		o.JWKSURI != "https://auth.corp/.well-known/jwks" || o.ClockSkew != 5*time.Second || o.JWKSTTL != 120*time.Second ||
		o.JWKSMinRefresh != time.Second || o.HTTPTimeout != 3*time.Second || !o.Introspect {
		t.Fatalf("OptionsFromEnv: %+v", o)
	}
	os.Unsetenv("TSL_AUTH_CLOCK_SKEW_SECONDS")
	d := OptionsFromEnv().withDefaults()
	if d.ClockSkew != 30*time.Second || d.Now == nil || d.HTTPClient == nil || d.HTTPClient.Timeout != 3*time.Second {
		t.Fatalf("умолчания: %+v", d)
	}
	if _, err := New(Options{}); err == nil {
		t.Fatal("New без Issuer должен вернуть ошибку")
	}
	if _, err := NewTokenClient(Options{Issuer: "x"}); err == nil {
		t.Fatal("NewTokenClient без ClientID должен вернуть ошибку")
	}
}
