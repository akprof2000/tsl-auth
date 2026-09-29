// Package tslauth — клиентская библиотека TSL Auth для Go: проверка access-токенов (RS256, JWKS с кэшем),
// principal с правами, middleware для net/http и клиент токенов (client_credentials, exchange, refresh,
// password, authorization_code, introspect, revoke). Только стандартная библиотека — работает в закрытом контуре.
//
// Поведение задано контрактом docs/client-contract.md репозитория: порядок проверок и коды ошибок (§2),
// кэш ключей (§3), состав principal (§4), формат ответов 401/403 (§5), клиент токенов (§6).
//
// Подключение одной строкой (настройки из переменных TSL_AUTH_*):
//
//	v, err := tslauth.New(tslauth.OptionsFromEnv())
//	mux.Handle("/orders", v.Protect(ordersHandler, tslauth.Require{Permission: "orders.read"}))
package tslauth
