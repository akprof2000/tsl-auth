import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Download, ExternalLink, KeyRound, LogOut, MessageCircle, ShieldCheck, Smartphone, Users } from "lucide-react";
import { cabinetUrl, userManager } from "../auth";
import { useSession } from "../session";
import { Avatar, PageHeader } from "../components/ui";

type InstallEvent = Event & { prompt: () => Promise<void> };

/** Профиль: роли и разрешения из токена, ссылки в личный кабинет TSL Auth, установка PWA. */
export default function ProfilePage() {
  const { me, roles, roleTitle, can, logout } = useSession();
  const [claims, setClaims] = useState<Record<string, unknown> | null>(null);
  const [install, setInstall] = useState<InstallEvent | null>(null);

  useEffect(() => {
    userManager.getUser().then((u) => {
      if (!u) return;
      const payload = u.access_token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/");
      setClaims(JSON.parse(decodeURIComponent(escape(atob(payload)))));
    });
    const onPrompt = (e: Event) => { e.preventDefault(); setInstall(e as InstallEvent); };
    addEventListener("beforeinstallprompt", onPrompt);
    return () => removeEventListener("beforeinstallprompt", onPrompt);
  }, []);

  const links = [
    { icon: KeyRound, label: "Сменить пароль", href: cabinetUrl("Account") },
    { icon: MessageCircle, label: "Привязать бота (код привязки)", href: cabinetUrl("Account/Messenger") },
    { icon: ShieldCheck, label: "Сеансы и персональные токены", href: cabinetUrl("Account") }
  ];

  return (
    <>
      <PageHeader title="Профиль" />
      <div className="grid gap-6 lg:grid-cols-[360px_1fr]">
        <div className="space-y-6">
          <div className="card overflow-hidden">
            <div className="h-24 bg-gradient-to-br from-brand-500 via-violet-500 to-fuchsia-500" />
            <div className="-mt-10 px-6 pb-6">
              <div className="rounded-full border-4 border-white inline-block dark:border-[#0b1020]"><Avatar name={me.displayName} size={72} /></div>
              <div className="mt-2 text-xl font-semibold">{me.displayName}</div>
              <div className="text-sm text-slate-500">@{me.userName}</div>
              <div className="mt-4 flex flex-wrap gap-1.5">
                {me.roles.map((r) => <span key={r} className="chip bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200"><ShieldCheck className="size-3" />{roleTitle(r)}</span>)}
                {me.roles.length === 0 && <span className="text-sm text-slate-400">Ролей нет</span>}
              </div>
            </div>
          </div>
          <div className="card divide-y divide-slate-100 dark:divide-white/5">
            {links.map((l) => (
              <a key={l.label} href={l.href} target="_blank" rel="noopener" className="flex items-center gap-3 px-5 py-3.5 text-sm hover:bg-slate-50 dark:hover:bg-white/5">
                <l.icon className="size-4 text-brand-500" /><span className="flex-1">{l.label}</span><ExternalLink className="size-3.5 text-slate-400" />
              </a>
            ))}
            {can("users.manage") && (
              <Link to="/users" className="flex items-center gap-3 px-5 py-3.5 text-sm hover:bg-slate-50 lg:hidden dark:hover:bg-white/5"><Users className="size-4 text-brand-500" />Пользователи</Link>
            )}
            {install && (
              <button onClick={() => install.prompt().then(() => setInstall(null))} className="flex w-full items-center gap-3 px-5 py-3.5 text-sm hover:bg-slate-50 dark:hover:bg-white/5">
                <Download className="size-4 text-brand-500" />Установить приложение
              </button>
            )}
            <button onClick={logout} className="flex w-full items-center gap-3 px-5 py-3.5 text-sm text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-500/10"><LogOut className="size-4" />Выйти</button>
          </div>
          <div className="card flex gap-3 p-5 text-sm text-slate-500">
            <Smartphone className="size-5 shrink-0 text-brand-500" />
            Это PWA: на телефоне откройте меню браузера и выберите «Добавить на главный экран».
          </div>
        </div>

        <div className="space-y-6">
          <div className="card p-6">
            <div className="mb-1 font-semibold">Права в документообороте</div>
            <p className="mb-4 text-sm text-slate-500">Разрешения приходят из матрицы приложения в TSL Auth (claim <code>permissions</code>).</p>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="py-2 pr-4 font-medium">Роль</th>
                    {["documents.view", "documents.create", "documents.review", "documents.approve", "documents.archive", "dashboard.view", "users.manage"].map((p) =>
                      <th key={p} className="px-2 py-2 text-center font-mono text-[10px] font-medium normal-case">{p.replace("documents.", "doc.")}</th>)}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                  {roles.map((r) => (
                    <tr key={r.name} className={me.roles.includes(r.name) ? "bg-brand-50/60 dark:bg-brand-500/10" : ""}>
                      <td className="py-2.5 pr-4 font-medium">{r.title}{me.roles.includes(r.name) && <span className="ml-2 text-xs text-brand-600">· вы</span>}</td>
                      {["documents.view", "documents.create", "documents.review", "documents.approve", "documents.archive", "dashboard.view", "users.manage"].map((p) => (
                        <td key={p} className="px-2 text-center">{r.permissions.includes(p) ? <span className="inline-block size-2.5 rounded-full bg-emerald-500" /> : <span className="inline-block size-2.5 rounded-full bg-slate-200 dark:bg-white/10" />}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="card p-6">
            <div className="mb-3 font-semibold">Access-токен (claims)</div>
            <pre className="scrollbar-thin max-h-96 overflow-auto rounded-xl bg-slate-950 p-4 text-xs leading-relaxed text-slate-200">{claims ? JSON.stringify(claims, null, 2) : "…"}</pre>
          </div>
        </div>
      </div>
    </>
  );
}
