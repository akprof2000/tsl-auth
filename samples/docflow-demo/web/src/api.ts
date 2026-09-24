import { accessToken, userManager } from "./auth";

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

/** Запрос к API документооборота с access-токеном; 401 — сессия закончилась, отправляем на вход. */
export async function api<T = unknown>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const token = await accessToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = init.body;
  if (init.json !== undefined) { headers.set("Content-Type", "application/json"); body = JSON.stringify(init.json); }
  const res = await fetch(path, { ...init, headers, body });
  if (res.status === 401) {
    await userManager.removeUser();
    await userManager.signinRedirect({ state: location.pathname });
    throw new ApiError("Требуется вход", 401);
  }
  const text = await res.text();
  let data: any = null;
  if (text) { try { data = JSON.parse(text); } catch { data = text; } }
  if (!res.ok) throw new ApiError((data && (data.detail || data.title)) || `Ошибка ${res.status}`, res.status);
  return data as T;
}

export type Me = { id: string; userName: string; displayName: string; roles: string[]; permissions: string[] };
export type Status = "Draft" | "InReview" | "Approved" | "Rejected" | "Archived";
export type DocSummary = {
  id: string; number: string; title: string; type: string; status: Status; authorName: string; createdAt: string; updatedAt: string;
  version: number; stepsTotal: number; stepsDone: number; currentStep: { kind: string; assignee: string } | null; isMine: boolean; myTask: boolean;
};
export type Step = {
  id: string; order: number; kind: "Review" | "Approve"; status: "Pending" | "Active" | "Done" | "Rejected";
  assigneeRole: string | null; assigneeUserId: string | null; assigneeName: string | null; decidedByName: string | null; decidedAt: string | null; comment: string | null;
};
export type DocFull = {
  id: string; number: string; title: string; type: string; status: Status; authorName: string; authorId: string; createdAt: string; updatedAt: string;
  version: number; content: string; steps: Step[];
  versions: { id: string; number: number; title: string; content: string; createdByName: string; createdAt: string; note: string | null }[];
  comments: { id: string; authorName: string; authorId: string; text: string; createdAt: string }[];
  attachments: { id: string; fileName: string; contentType: string; size: number; uploadedByName: string; createdAt: string }[];
  history: { at: string; actorName: string; action: string; details: string | null }[];
  can: { edit: boolean; submit: boolean; delete: boolean; decide: boolean; archive: boolean; attach: boolean };
};
export type Role = { name: string; title: string; description: string | null; permissions: string[] };
export type DirUser = { id: string; userName: string; name: string; roles: string[] };
export type AppUser = {
  id: string; userName: string; email: string | null; displayName: string | null; isActive: boolean; hasPassword: boolean;
  mustChangePassword: boolean; createdByThisApp: boolean; roles: string[];
};
export type AccessRequest = {
  id: string; userId: string; userName: string | null; email: string | null; role: string; roleTitle: string; status: string;
  comment: string | null; createdAt: string;
};
export type Notice = { id: string; text: string; link: string | null; kind: string; createdAt: string; readAt: string | null };
export type ChatButton = { label: string; send?: string | null; url?: string | null; style: string };
export type ChatMessage = { id: string; from: "user" | "bot"; text: string; at: string; kind: string; buttons: ChatButton[]; secret?: string | null };

/** Скачивание вложения с токеном (обычная ссылка не передаст заголовок Authorization). */
export async function download(path: string, fileName: string) {
  const token = await accessToken();
  const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new ApiError("Не удалось скачать файл", res.status);
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: fileName });
  a.click();
  URL.revokeObjectURL(url);
}
