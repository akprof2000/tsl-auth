package tslauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMiddleware — реальный HTTP-сервер на свободном порту с тремя маршрутами (§8): /me, /orders, /orders/write.
func TestMiddleware(t *testing.T) {
	v := loadVectors(t)
	verifier, err := New(v.baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/me", verifier.Protect(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			t.Error("principal не в контексте")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"username": p.Username, "subjectType": p.SubjectType})
	}, Require{}))
	orders := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"orders":[]}`)) }
	mux.Handle("/orders", verifier.Protect(orders, Require{Permission: "orders.read"}))
	mux.Handle("/orders/write", verifier.Middleware(Require{Permission: "orders.write"})(http.HandlerFunc(orders)))
	mux.Handle("/any", verifier.Protect(orders, Require{AnyPermission: []string{"orders.write", "orders.read"}}))
	mux.Handle("/admin", verifier.Protect(orders, Require{Role: "admin"}))
	mux.Handle("/mfa", verifier.Protect(orders, Require{MFA: true}))
	mux.Handle("/users-only", verifier.Protect(orders, Require{SubjectType: "user"}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	call := func(path, auth string) (int, http.Header, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return resp.StatusCode, resp.Header, body
	}
	user := "Bearer " + v.caseToken(t, "ok_user")
	viewer := "bearer " + v.caseToken(t, "ok_viewer") // регистр слова Bearer не важен
	client := "Bearer " + v.caseToken(t, "ok_client")

	// 401 без токена.
	status, h, body := call("/me", "")
	if status != 401 || body["error"] != "invalid_token" || body["error_description"] != "missing" {
		t.Fatalf("без токена: %d %v", status, body)
	}
	if h.Get("WWW-Authenticate") != `Bearer realm="tsl-auth", error="invalid_token", error_description="missing"` {
		t.Fatalf("WWW-Authenticate: %q", h.Get("WWW-Authenticate"))
	}
	if h.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type: %q", h.Get("Content-Type"))
	}
	// 401 с пустым Bearer и с другой схемой — missing.
	if status, _, body = call("/me", "Bearer "); status != 401 || body["error_description"] != "missing" {
		t.Fatalf("пустой Bearer: %d %v", status, body)
	}
	if status, _, body = call("/me", "Basic abc"); status != 401 || body["error_description"] != "missing" {
		t.Fatalf("Basic: %d %v", status, body)
	}
	// 401 с испорченным токеном.
	status, h, body = call("/me", "Bearer "+v.caseToken(t, "tampered_payload"))
	if status != 401 || body["error_description"] != "bad_signature" {
		t.Fatalf("испорченный токен: %d %v", status, body)
	}
	if h.Get("WWW-Authenticate") != `Bearer realm="tsl-auth", error="invalid_token", error_description="bad_signature"` {
		t.Fatalf("WWW-Authenticate: %q", h.Get("WWW-Authenticate"))
	}
	if status, _, body = call("/me", "Bearer not.a.jwt"); status != 401 || body["error_description"] != "malformed" {
		t.Fatalf("garbage: %d %v", status, body)
	}
	// 200 для ok_user на /me с username.
	if status, _, body = call("/me", user); status != 200 || body["username"] != "sdk-operator" {
		t.Fatalf("/me: %d %v", status, body)
	}
	// 200 для viewer на /orders, 403 на /orders/write.
	if status, _, _ = call("/orders", viewer); status != 200 {
		t.Fatalf("/orders viewer: %d", status)
	}
	status, h, body = call("/orders/write", viewer)
	if status != 403 || body["error"] != "insufficient_permissions" || body["error_description"] != v.Audience+":orders.write" {
		t.Fatalf("/orders/write viewer: %d %v", status, body)
	}
	if want := `Bearer realm="tsl-auth", error="insufficient_permissions", error_description="` + v.Audience + `:orders.write"`; h.Get("WWW-Authenticate") != want {
		t.Fatalf("WWW-Authenticate 403: %q", h.Get("WWW-Authenticate"))
	}
	if status, _, _ = call("/orders/write", user); status != 200 {
		t.Fatalf("/orders/write user: %d", status)
	}
	// anyPermission: viewer имеет orders.read — 200.
	if status, _, _ = call("/any", viewer); status != 200 {
		t.Fatalf("/any viewer: %d", status)
	}
	// role/mfa/subjectType.
	status, h, body = call("/admin", user)
	if status != 403 || body["error"] != "insufficient_role" || h.Get("WWW-Authenticate") != `Bearer realm="tsl-auth", error="insufficient_role", error_description="`+v.Audience+`:admin"` {
		t.Fatalf("/admin: %d %v %q", status, body, h.Get("WWW-Authenticate"))
	}
	if status, _, body = call("/mfa", user); status != 403 || body["error"] != "mfa_required" {
		t.Fatalf("/mfa: %d %v", status, body)
	}
	if status, _, body = call("/users-only", client); status != 403 || body["error"] != "subject_type_not_allowed" {
		t.Fatalf("/users-only client: %d %v", status, body)
	}
	if status, _, _ = call("/users-only", user); status != 200 {
		t.Fatalf("/users-only user: %d", status)
	}
}

func TestFromContextEmpty(t *testing.T) {
	if p, ok := FromContext(context.Background()); ok || p != nil {
		t.Fatal("пустой контекст не должен содержать principal")
	}
}
