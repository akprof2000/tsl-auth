package tslauth

import (
	"strings"
	"time"
)

// Actor — цепочка token exchange (claim act): кто действует от имени субъекта.
type Actor struct {
	Sub string
	Act *Actor // вложенная цепочка, если обмен был многоступенчатым
}

// Principal — результат успешной проверки токена (контракт §4).
type Principal struct {
	Subject     string // sub: id пользователя или client_id сервиса
	SubjectType string // subject_type: user / client
	Username    string // preferred_username (у сервисных токенов пусто)
	Name        string
	Email       string

	Roles          []string // роли этого API без префикса "<audience>:"
	Permissions    []string // разрешения этого API без префикса
	AllRoles       []string // role как в токене, с префиксами (для шлюзов)
	AllPermissions []string // permissions как в токене
	Scopes         []string // scope через пробел → список
	Amr            []string // amr

	ExpiresAt time.Time      // exp
	Claims    map[string]any // весь payload

	actor *Actor
}

// HasPermission — есть ли разрешение этого API (короткая форма "orders.read"; полная форма не принимается).
func (p *Principal) HasPermission(permission string) bool { return contains(p.Permissions, permission) }

// HasRole — есть ли роль этого API (короткая форма).
func (p *Principal) HasRole(role string) bool { return contains(p.Roles, role) }

// IsMFA — вход со вторым фактором (amr содержит "mfa").
func (p *Principal) IsMFA() bool { return contains(p.Amr, "mfa") }

// Actor — цепочка token exchange или nil, если токен получен не обменом.
func (p *Principal) Actor() *Actor { return p.actor }

// newPrincipal строит principal из payload по правилам §4.
func newPrincipal(claims map[string]any, audience string) *Principal {
	p := &Principal{
		Subject:        str(claims["sub"]),
		SubjectType:    str(claims["subject_type"]),
		Username:       str(claims["preferred_username"]),
		Name:           str(claims["name"]),
		Email:          str(claims["email"]),
		AllRoles:       stringList(claims["role"]),
		AllPermissions: stringList(claims["permissions"]),
		Amr:            stringList(claims["amr"]),
		Scopes:         strings.Fields(str(claims["scope"])),
		Claims:         claims,
		actor:          parseActor(claims["act"]),
	}
	p.Roles = stripPrefix(p.AllRoles, audience)
	p.Permissions = stripPrefix(p.AllPermissions, audience)
	if exp, ok := numClaim(claims["exp"]); ok {
		p.ExpiresAt = time.Unix(exp, 0)
	}
	return p
}

func parseActor(v any) *Actor {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return &Actor{Sub: str(m["sub"]), Act: parseActor(m["act"])}
}

// stripPrefix оставляет только значения "<audience>:<x>" и обрезает префикс.
func stripPrefix(values []string, audience string) []string {
	out := []string{}
	if audience == "" {
		return out
	}
	prefix := audience + ":"
	for _, v := range values {
		if rest, ok := strings.CutPrefix(v, prefix); ok && rest != "" {
			out = append(out, rest)
		}
	}
	return out
}

// stringList нормализует claim-список: строка (одно значение) или массив → список; отсутствие → пустой список.
func stringList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// numClaim читает числовой claim (JSON-число приходит как float64).
func numClaim(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	}
	return 0, false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
