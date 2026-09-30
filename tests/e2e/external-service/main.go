// Сквозной сценарий «внешний сервис» на живом стенде (образец интеграции для 1c-import): администратор регистрирует
// сервис-владелец, оператор входит и сервис получает делегированный токен (token exchange), агент генерирует ключ ES256,
// сервис регистрирует подчинённого через /api/app/clients, агент входит по private_key_jwt, сервис проверяет его токен
// Go SDK (Verifier), затем ротация ключа с двумя kid, отключение (introspection active=false, событие application.disabled),
// журнал владельца, удаление; отказы: чужой ключ, повтор jti, сервисный токен на изменение, роль вне списка, обход через Admin API.
// Запуск при поднятом стенде (docker compose up -d): cd tests/e2e/external-service && go run .
// Переменные: TSL_AUTH_ISSUER (http://localhost:8080/), ADMIN_CLIENT_ID (admin-cli), ADMIN_CLIENT_SECRET.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	tslauth "github.com/akprof2000/tsl-auth/sdk/go"
)

var (
	issuer      = env("TSL_AUTH_ISSUER", "http://localhost:8080/")
	base        = strings.TrimSuffix(issuer, "/")
	adminID     = env("ADMIN_CLIENT_ID", "admin-cli")
	adminSecret = env("ADMIN_CLIENT_SECRET", "demo-admin-cli-secret-2026")
	suffix      = fmt.Sprintf("%x", time.Now().Unix()%1000000)
	owner       = "erp-import-api-" + suffix
	web         = "erp-import-web-" + suffix
	operator    = "operator-" + suffix
	password    = "Op-" + suffix + "-Passw0rd!"
	failed      int
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func check(name string, ok bool, detail string) {
	mark := "✓"
	if !ok {
		mark = "✗"
		failed++
	}
	fmt.Printf("  %s %s", mark, name)
	if detail != "" {
		fmt.Printf(" — %s", detail)
	}
	fmt.Println()
}

func call(method, path, token string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		var arr []any
		if json.Unmarshal(raw, &arr) == nil {
			m = map[string]any{"items": arr}
		} else {
			m = map[string]any{"raw": string(raw)}
		}
	}
	return resp.StatusCode, m
}

func tokenForm(form url.Values) (int, map[string]any) {
	resp, err := http.PostForm(base+"/connect/token", form)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func main() {
	ctx := context.Background()
	fmt.Printf("Стенд %s, внешний сервис %s\n", issuer, owner)

	// ---------- 1. Администратор регистрирует внешний сервис ----------
	fmt.Println("1. Регистрация внешнего сервиса администратором")
	_, adm := tokenForm(url.Values{"grant_type": {"client_credentials"}, "client_id": {adminID}, "client_secret": {adminSecret}, "scope": {"tsl-auth-admin"}})
	admin := str(adm, "access_token")
	check("токен Admin API получен", admin != "", "")
	st, created := call("POST", "/api/admin/applications", admin, map[string]any{
		"clientId": owner, "displayName": "ERP Import API (внешний сервис)", "clientType": "confidential",
		"grantTypes": []string{"client_credentials", "token_exchange"}, "selfManagement": true})
	ownerSecret := str(created, "clientSecret")
	check("владелец зарегистрирован (confidential, client_credentials + token_exchange, самоуправление)", st == 201 && ownerSecret != "", fmt.Sprintf("HTTP %d", st))
	for _, p := range []string{"agents.manage", "upload"} {
		call("POST", "/api/admin/applications/"+owner+"/permissions", admin, map[string]any{"name": p})
	}
	call("POST", "/api/admin/applications/"+owner+"/roles", admin, map[string]any{"name": "agents-admin", "displayName": "Администратор агентов", "permissions": []string{"agents.manage"}})
	call("POST", "/api/admin/applications/"+owner+"/roles", admin, map[string]any{"name": "uploader", "displayName": "Агент загрузки", "permissions": []string{"upload"}})
	call("POST", "/api/admin/applications/"+owner+"/roles", admin, map[string]any{"name": "viewer", "permissions": []string{}})
	st, _ = call("POST", "/api/admin/applications", admin, map[string]any{
		"clientId": web, "displayName": "ERP Import UI", "clientType": "public", "grantTypes": []string{"password"}, "scopes": []string{owner}})
	check("public-клиент интерфейса для входа оператора", st == 201, "")
	st, user := call("POST", "/api/admin/users", admin, map[string]any{
		"userName": operator, "email": operator + "@erp.local", "displayName": "Оператор импорта", "password": password,
		"roles": []map[string]string{{"clientId": owner, "role": "agents-admin"}}})
	check("оператор с ролью agents-admin (разрешение agents.manage)", st == 201, "")
	_ = user
	st, pol := call("PUT", "/api/admin/applications/"+owner+"/managed-clients-policy", admin, map[string]any{
		"prefix": "import-agent-", "roles": []string{"uploader"}, "authMethods": []string{"private_key_jwt"},
		"maxClients": 200, "accessTokenLifetime": 5, "requireDelegation": true, "managePermission": "agents.manage"})
	check("политика подчинённых клиентов задана администратором", st == 200 && str(pol, "prefix") == "import-agent-", fmt.Sprintf("HTTP %d", st))
	st, _ = call("PUT", "/api/admin/applications/"+owner+"/managed-clients-policy", admin, map[string]any{"prefix": "import-agent-", "roles": []string{"nope"}})
	check("политика с ролью вне матрицы отвергнута (400)", st == 400, "")
	st, disc := call("GET", "/.well-known/openid-configuration", "", nil)
	methods := fmt.Sprint(disc["token_endpoint_auth_methods_supported"])
	check("discovery: private_key_jwt и ES256", st == 200 && strings.Contains(methods, "private_key_jwt") && strings.Contains(fmt.Sprint(disc["token_endpoint_auth_signing_alg_values_supported"]), "ES256"), "")

	// ---------- 2. Внешний сервис: делегированный токен оператора ----------
	fmt.Println("2. Внешний сервис получает делегированный токен оператора")
	st, opTok := tokenForm(url.Values{"grant_type": {"password"}, "client_id": {web}, "username": {operator}, "password": {password}, "scope": {owner}})
	check("оператор вошёл в интерфейс сервиса (password grant, aud "+owner+")", st == 200, "")
	svc, err := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: owner, ClientSecret: ownerSecret})
	if err != nil {
		panic(err)
	}
	delegated, err := svc.Exchange(ctx, str(opTok, "access_token"), "tsl-auth-app")
	check("token exchange → делегированный токен (sub = оператор, act.sub = сервис)", err == nil, fmt.Sprint(err))
	service, err := svc.ClientCredentials(ctx, "tsl-auth-app")
	check("сервисный токен владельца (client_credentials)", err == nil, fmt.Sprint(err))
	st, _ = call("POST", "/api/app/clients", service.AccessToken, map[string]any{"roles": []string{"uploader"}, "requestSecret": true})
	check("сервисный токен на изменение подчинённых — 403 (нужен оператор)", st == 403, fmt.Sprintf("HTTP %d", st))
	st, list := call("GET", "/api/app/clients", service.AccessToken, nil)
	items, _ := list["items"].([]any)
	check("сервисный токен на чтение списка — 200", st == 200 && items != nil, fmt.Sprint(len(items)))

	// ---------- 3. Агент: ключ и регистрация через владельца ----------
	fmt.Println("3. Агент генерирует ключ, сервис регистрирует подчинённого делегированным токеном")
	agentPEM, _ := tslauth.GenerateClientKeyPEM()
	agentKey, _ := tslauth.ParseClientKeyPEM(agentPEM)
	st, reg := call("POST", "/api/app/clients", delegated.AccessToken, map[string]any{
		"clientIdSuffix": "wh-" + suffix, "displayName": "Агент склада", "roles": []string{"uploader"}, "jwks": tslauth.PublicJWKS(agentKey)})
	client, _ := reg["client"].(map[string]any)
	agentID := str(client, "clientId")
	check("подчинённый создан: "+agentID, st == 201 && strings.HasPrefix(agentID, "import-agent-"), fmt.Sprintf("HTTP %d %v", st, reg["detail"]))
	keys, _ := client["keys"].([]any)
	kid := ""
	if len(keys) > 0 {
		first, _ := keys[0].(map[string]any)
		kid = str(first, "kid")
	}
	check("kid = отпечаток RFC 7638 ключа агента", kid == tslauth.KeyID(agentKey), kid)
	st, _ = call("POST", "/api/app/clients", delegated.AccessToken, map[string]any{"roles": []string{"viewer"}, "jwks": tslauth.PublicJWKS(agentKey)})
	check("роль вне белого списка (viewer) — 400", st == 400, "")
	st, _ = call("POST", "/api/app/clients", delegated.AccessToken, map[string]any{"roles": []string{"uploader"}, "requestSecret": true})
	check("секрет при политике «только ключ» — 400", st == 400, "")
	st, _ = call("PUT", "/api/admin/applications/"+agentID, admin, map[string]any{"clientId": agentID, "clientType": "confidential", "grantTypes": []string{"client_credentials"}, "scopes": []string{"tsl-auth-admin"}})
	check("Admin API не может расширить подчинённого (400)", st == 400, "")
	st, dto := call("GET", "/api/admin/applications/"+agentID, admin, nil)
	check("админ видит владельца подчинённого", st == 200 && str(dto, "owner") == owner, str(dto, "owner"))

	// ---------- 4. Агент входит по ключу, сервис проверяет токен ----------
	fmt.Println("4. Агент входит по private_key_jwt, внешний сервис проверяет его токен своим SDK")
	agent, _ := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: agentID, ClientKeyPEM: agentPEM})
	ts, err := agent.ClientCredentials(ctx, owner)
	check("токен по private_key_jwt (без секрета)", err == nil, fmt.Sprint(err))
	verifier, _ := tslauth.New(tslauth.Options{Issuer: issuer, Audience: owner})
	var p *tslauth.Principal
	if err == nil {
		p, err = verifier.Verify(ctx, ts.AccessToken)
	}
	check("сервис принял токен агента (Verifier, aud = сервис)", err == nil && p != nil && p.SubjectType == "client" && p.Subject == agentID, fmt.Sprint(err))
	check("в токене роль uploader и разрешение upload", p != nil && p.HasRole("uploader") && p.HasPermission("upload"), fmt.Sprint(p != nil && p.Roles != nil))
	check("срок токена из политики — 5 минут", ts != nil && time.Until(ts.ExpiresAt) > 4*time.Minute && time.Until(ts.ExpiresAt) <= 5*time.Minute, "")
	intro, err := svc.Introspect(ctx, ts.AccessToken)
	check("introspection владельцем: active=true", err == nil && intro.Active, "")
	impostor, _ := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: agentID, ClientKeyPEM: mustPEM()})
	_, err = impostor.ClientCredentials(ctx, owner)
	check("чужой ключ с тем же client_id — invalid_client", err != nil && strings.Contains(err.Error(), "invalid_client"), fmt.Sprint(err))
	_, ass := replayAssertion(agentPEM, agentID)
	st1, r1 := tokenForm(url.Values{"grant_type": {"client_credentials"}, "client_id": {agentID}, "scope": {owner},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {ass}})
	st2, r2 := tokenForm(url.Values{"grant_type": {"client_credentials"}, "client_id": {agentID}, "scope": {owner},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {ass}})
	check("повтор того же assertion (jti) — отказ", st1 == 200 && st2 != 200 && str(r2, "error") == "invalid_client", fmt.Sprintf("%d/%d %v", st1, st2, r1["error"]))
	st, _ = tokenForm(url.Values{"grant_type": {"client_credentials"}, "client_id": {agentID}, "client_secret": {"x"}, "scope": {"tsl-auth-admin"}})
	check("чужой scope tsl-auth-admin агенту недоступен", st != 200, "")

	// ---------- 5. Ротация ключа ----------
	fmt.Println("5. Смена ключа агента с двумя kid")
	newPEM, _ := tslauth.GenerateClientKeyPEM()
	newKey, _ := tslauth.ParseClientKeyPEM(newPEM)
	st, _ = call("PUT", "/api/app/clients/"+agentID+"/keys", delegated.AccessToken, map[string]any{"jwks": map[string]any{"keys": []map[string]string{tslauth.PublicJWK(agentKey), tslauth.PublicJWK(newKey)}}})
	check("два ключа зарегистрированы", st == 200, fmt.Sprintf("HTTP %d", st))
	agentNew, _ := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: agentID, ClientKeyPEM: newPEM})
	_, errOld := agent.ClientCredentials(ctx, owner)
	_, errNew := agentNew.ClientCredentials(ctx, owner)
	check("оба ключа принимаются", errOld == nil && errNew == nil, fmt.Sprint(errOld, errNew))
	call("PUT", "/api/app/clients/"+agentID+"/keys", delegated.AccessToken, map[string]any{"jwks": tslauth.PublicJWKS(newKey)})
	agentOld, _ := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: agentID, ClientKeyPEM: agentPEM})
	_, errOld = agentOld.ClientCredentials(ctx, owner)
	check("старый ключ после удаления отклонён", errOld != nil, "")

	// ---------- 6. Отключение, аудит, удаление ----------
	fmt.Println("6. Отключение агента, журнал, удаление")
	tsBefore, _ := agentNew.ClientCredentials(ctx, owner)
	_, cur := call("GET", "/api/admin/events?after=0&limit=500", admin, nil)
	cursor, _ := cur["next"].(float64)
	st, d := call("POST", "/api/app/clients/"+agentID+"/disable", delegated.AccessToken, map[string]any{})
	check("агент отключён оператором", st == 200 && d["disabled"] == true, "")
	agentNew2, _ := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: agentID, ClientKeyPEM: newPEM})
	_, err = agentNew2.ClientCredentials(ctx, owner)
	check("отключённый агент не получает токен", err != nil, "")
	intro, _ = svc.Introspect(ctx, tsBefore.AccessToken)
	check("introspection ранее выданного токена: active=false", !intro.Active, "")
	_, errV := verifier.Verify(ctx, tsBefore.AccessToken)
	check("локальная проверка JWT до истечения ещё проходит (ожидаемо: срок 5 мин; для мгновенного отсечения — вебхук application.disabled или TSL_AUTH_INTROSPECT)", errV == nil, "")
	time.Sleep(1500 * time.Millisecond) // лента отдаёт события старше 1 с (окно «успокоения» курсора)
	st, ev := call("GET", fmt.Sprintf("/api/admin/events?after=%d&limit=500&types=application.disabled", int64(cursor)), admin, nil)
	found := false
	if evs, ok := ev["events"].([]any); ok {
		for _, e := range evs {
			item, _ := e.(map[string]any)
			data, _ := item["data"].(map[string]any)
			if str(data, "clientId") == agentID && str(data, "owner") == owner {
				found = true
			}
		}
	}
	check("событие application.disabled с владельцем в ленте", st == 200 && found, "")
	call("POST", "/api/app/clients/"+agentID+"/enable", delegated.AccessToken, map[string]any{})
	_, err = agentNew2.ClientCredentials(ctx, owner)
	check("после включения токен снова выдаётся", err == nil, fmt.Sprint(err))
	time.Sleep(1500 * time.Millisecond) // аудит пишется пачками в фоне
	st, audit := call("GET", "/api/app/audit?type=managed_client.change", service.AccessToken, nil)
	actions := map[string]bool{}
	actorOK := false
	if items, ok := audit["items"].([]any); ok {
		for _, it := range items {
			m, _ := it.(map[string]any)
			det, _ := m["details"].(map[string]any)
			actions[str(det, "action")] = true
			if str(det, "action") == "created" && strings.HasPrefix(str(m, "actor"), "user:") && str(det, "via") == owner {
				actorOK = true
			}
		}
	}
	check("журнал владельца: created/keys_changed/disabled/enabled, актор — оператор через сервис", st == 200 && actions["created"] && actions["keys_changed"] && actions["disabled"] && actions["enabled"] && actorOK, fmt.Sprint(actions))
	st, _ = call("DELETE", "/api/app/clients/"+agentID, delegated.AccessToken, nil)
	check("агент удалён", st == 204, fmt.Sprintf("HTTP %d", st))
	agentNew3, _ := tslauth.NewTokenClient(tslauth.Options{Issuer: issuer, ClientID: agentID, ClientKeyPEM: newPEM}) // без кэша SDK
	_, err = agentNew3.ClientCredentials(ctx, owner)
	check("после удаления токен не выдаётся", err != nil, "")
	st, _ = call("GET", "/api/app/clients/"+agentID, delegated.AccessToken, nil)
	check("карточка удалённого — 404", st == 404, "")

	// ---------- 7. Уборка ----------
	st, _ = call("DELETE", "/api/admin/applications/"+owner, admin, nil)
	call("DELETE", "/api/admin/applications/"+web, admin, nil)
	createdUser, _ := user["user"].(map[string]any)
	if id := str(createdUser, "id"); id != "" {
		call("DELETE", "/api/admin/users/"+id, admin, nil)
	}
	check("уборка: сервис, интерфейс и оператор удалены", st == 204, "")

	if failed > 0 {
		fmt.Printf("\nПРОВАЛЕНО проверок: %d\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nВСЕ ПРОВЕРКИ ПРОШЛИ")
}

func mustPEM() string {
	p, _ := tslauth.GenerateClientKeyPEM()
	return p
}

// replayAssertion — assertion RFC 7523 «вручную» (для проверки повтора jti): ES256, typ client-authentication+jwt.
func replayAssertion(pemText, clientID string) (string, string) {
	key, _ := tslauth.ParseClientKeyPEM(pemText)
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "client-authentication+jwt", "kid": tslauth.KeyID(key)})
	jti := fmt.Sprintf("replay-%d", now.UnixNano())
	payload, _ := json.Marshal(map[string]any{"iss": clientID, "sub": clientID, "aud": issuer, "jti": jti, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(60 * time.Second).Unix()})
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return jti, input + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
