// Вход через TSL Auth: authorization code + PKCE прямо в браузере (public-клиент docflow-web).
// Токены хранятся в sessionStorage (не localStorage): закрыли вкладку — сессия приложения закончилась;
// пока вкладка открыта, access-токен обновляется refresh-токеном автоматически.
import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";

declare global {
  interface Window { DOCFLOW_CONFIG?: { issuer: string; clientId: string; apiClientId: string } }
}

export const config = window.DOCFLOW_CONFIG ?? { issuer: "http://localhost:8080/", clientId: "docflow-web", apiClientId: "docflow-api" };

export const userManager = new UserManager({
  authority: config.issuer,
  client_id: config.clientId,
  redirect_uri: `${location.origin}/callback`,
  post_logout_redirect_uri: `${location.origin}/`,
  response_type: "code",
  scope: `openid profile email roles offline_access ${config.apiClientId}`,
  automaticSilentRenew: true,
  userStore: new WebStorageStateStore({ store: sessionStorage }),
  loadUserInfo: false
});

/** Страница личного кабинета TSL Auth (смена пароля, привязка мессенджера и т. п.). */
export const cabinetUrl = (path = "Account") => new URL(path, config.issuer).toString();

export async function accessToken(): Promise<string | null> {
  const user: User | null = await userManager.getUser();
  if (!user) return null;
  if (user.expired) {
    try { return (await userManager.signinSilent())?.access_token ?? null; } catch { return null; }
  }
  return user.access_token;
}
