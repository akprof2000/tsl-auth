package tslauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Require — требования к запросу (контракт §5). Пустое значение — требование не проверяется.
type Require struct {
	Permission    string   // hasPermission(Permission), иначе 403 insufficient_permissions
	AnyPermission []string // хотя бы одно, иначе 403 insufficient_permissions
	Role          string   // hasRole(Role), иначе 403 insufficient_role
	MFA           bool     // IsMFA(), иначе 403 mfa_required
	SubjectType   string   // "user" / "client", иначе 403 subject_type_not_allowed
}

type ctxKey struct{}

// FromContext возвращает principal, положенный middleware в контекст запроса.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// NewContext кладёт principal в контекст (для тестов и собственных обёрток).
func NewContext(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// Middleware проверяет Bearer-токен и требования req; principal доступен через FromContext.
func (v *Verifier) Middleware(req Require) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := BearerToken(r)
			if !ok {
				writeUnauthorized(w, CodeMissing)
				return
			}
			p, err := v.Verify(r.Context(), token)
			if err != nil {
				code := ErrorCode(err)
				if code == "" {
					code = CodeMalformed
				}
				writeUnauthorized(w, code)
				return
			}
			if code, what := req.check(p, v.opts.Audience); code != "" {
				writeForbidden(w, code, what)
				return
			}
			next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), p)))
		})
	}
}

// Protect — Middleware для одного обработчика: mux.Handle("/orders", v.Protect(h, Require{Permission: "orders.read"})).
func (v *Verifier) Protect(h http.HandlerFunc, req Require) http.Handler {
	return v.Middleware(req)(h)
}

// BearerToken извлекает токен из Authorization: Bearer <jwt> (регистр слова Bearer не важен).
// false — заголовка нет, схема другая или токен пуст (код missing).
func BearerToken(r *http.Request) (string, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	token := strings.TrimSpace(h[7:])
	return token, token != ""
}

// check возвращает код 403 и описание требования ("<audience>:<permission>") либо "" при успехе.
func (r Require) check(p *Principal, audience string) (code, what string) {
	if r.Permission != "" && !p.HasPermission(r.Permission) {
		return "insufficient_permissions", audience + ":" + r.Permission
	}
	if len(r.AnyPermission) > 0 {
		ok := false
		names := make([]string, 0, len(r.AnyPermission))
		for _, perm := range r.AnyPermission {
			names = append(names, audience+":"+perm)
			ok = ok || p.HasPermission(perm)
		}
		if !ok {
			return "insufficient_permissions", strings.Join(names, " ")
		}
	}
	if r.Role != "" && !p.HasRole(r.Role) {
		return "insufficient_role", audience + ":" + r.Role
	}
	if r.MFA && !p.IsMFA() {
		return "mfa_required", "mfa"
	}
	if r.SubjectType != "" && p.SubjectType != r.SubjectType {
		return "subject_type_not_allowed", r.SubjectType
	}
	return "", ""
}

func writeUnauthorized(w http.ResponseWriter, code string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="tsl-auth", error="invalid_token", error_description="`+code+`"`)
	writeJSON(w, http.StatusUnauthorized, "invalid_token", code)
}

func writeForbidden(w http.ResponseWriter, code, what string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="tsl-auth", error="`+code+`", error_description="`+what+`"`)
	writeJSON(w, http.StatusForbidden, code, what)
}

func writeJSON(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "error_description": description})
}
