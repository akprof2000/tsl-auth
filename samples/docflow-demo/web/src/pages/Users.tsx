import { useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { Bot, Check, Copy, KeyRound, Link2, Mail, MoreHorizontal, Pencil, Search, ShieldCheck, Trash2, UserPlus, UserRoundPlus, X } from "lucide-react";
import { api, type AccessRequest, type AppUser, type Role } from "../api";
import { useSession } from "../session";
import { Avatar, Empty, ErrorBox, Modal, PageHeader, PageLoader, relTime, useAction, useLoad } from "../components/ui";
import { cabinetUrl } from "../auth";

function RolePicker({ roles, value, onChange }: { roles: Role[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="grid gap-2">
      {roles.map((r) => {
        const on = value.includes(r.name);
        return (
          <button type="button" key={r.name} onClick={() => onChange(on ? value.filter((x) => x !== r.name) : [...value, r.name])}
            className={clsx("flex items-start gap-3 rounded-xl border p-3 text-left transition", on ? "border-brand-400 bg-brand-50/70 dark:border-brand-400/50 dark:bg-brand-500/10" : "border-slate-200 hover:border-slate-300 dark:border-white/10")}>
            <span className={clsx("mt-0.5 grid size-5 shrink-0 place-items-center rounded-md border", on ? "border-brand-500 bg-brand-500 text-white" : "border-slate-300 dark:border-white/20")}>
              {on && <Check className="size-3.5" />}
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium">{r.title} <span className="font-mono text-xs text-slate-400">{r.name}</span></span>
              <span className="mt-1 flex flex-wrap gap-1">
                {r.permissions.map((p) => <span key={p} className="chip bg-slate-100 text-[11px] text-slate-600 dark:bg-white/5 dark:text-slate-400">{p}</span>)}
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

function Secret({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-400/20 dark:bg-emerald-500/10">
      <div className="mb-2 text-sm font-medium text-emerald-800 dark:text-emerald-200">{label}</div>
      <div className="flex gap-2">
        <code className="flex-1 break-all rounded-lg bg-white px-3 py-2 text-sm dark:bg-black/30">{value}</code>
        <button className="btn-outline" onClick={() => { navigator.clipboard.writeText(value); setCopied(true); }}>{copied ? <Check className="size-4" /> : <Copy className="size-4" />}</button>
      </div>
      <p className="mt-2 text-xs text-emerald-700 dark:text-emerald-300">Показывается один раз. Передайте сотруднику лично.</p>
    </div>
  );
}

export default function UsersPage() {
  const { roles, roleTitle, me } = useSession();
  const users = useLoad(() => api<AppUser[]>("/api/users"));
  const requests = useLoad(() => api<AccessRequest[]>("/api/users/requests"));
  const { busy, run } = useAction();
  const [tab, setTab] = useState<"users" | "requests">("users");
  const [q, setQ] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [modal, setModal] = useState<null | "create" | "link" | { edit: AppUser }>(null);
  const [secret, setSecret] = useState<null | { label: string; value: string }>(null);
  const [menu, setMenu] = useState<string | null>(null);
  const [form, setForm] = useState({ userName: "", email: "", displayName: "", roles: [] as string[], invite: false, login: "" });

  if (users.error) return <ErrorBox text={users.error} />;
  if (!users.data) return <PageLoader />;

  const list = users.data.filter((u) =>
    (!roleFilter || u.roles.includes(roleFilter)) &&
    (!q || [u.userName, u.displayName, u.email].some((x) => x?.toLowerCase().includes(q.toLowerCase()))));
  const pending = requests.data?.length ?? 0;

  const open = (m: typeof modal, u?: AppUser) => {
    setSecret(null);
    setForm({ userName: u?.userName ?? "", email: u?.email ?? "", displayName: u?.displayName ?? "", roles: u?.roles ?? [], invite: false, login: "" });
    setModal(m);
  };

  const create = async () => {
    const r = await run(() => api<{ temporaryPassword: string | null; invite: { link: string } | null }>("/api/users", { method: "POST", json: form }), "Пользователь создан");
    if (r) {
      users.reload();
      setSecret(r.invite ? { label: "Ссылка-приглашение (сотрудник сам задаст пароль)", value: r.invite.link } : { label: "Временный пароль (сменить при первом входе)", value: r.temporaryPassword ?? "" });
    }
  };
  const link = async () => {
    if (await run(() => api("/api/users/link", { method: "POST", json: { login: form.login, roles: form.roles } }), "Роли выданы")) { users.reload(); setModal(null); }
  };
  const saveEdit = async (u: AppUser) => {
    const ok = await run(async () => {
      if (u.createdByThisApp) await api(`/api/users/${u.id}`, { method: "PUT", json: { userName: form.userName, email: form.email, displayName: form.displayName } });
      await api(`/api/users/${u.id}/roles`, { method: "PUT", json: form.roles });
      return true;
    }, "Сохранено");
    if (ok) { users.reload(); setModal(null); }
  };

  return (
    <>
      <PageHeader title="Пользователи" subtitle={<>Сотрудники документооборота. Роли и их права настраиваются в TSL Auth, здесь — только назначаются.</>}
        actions={<>
          <button className="btn-outline" onClick={() => open("link")}><Link2 className="size-4" />Добавить существующего</button>
          <button className="btn-primary" onClick={() => open("create")}><UserPlus className="size-4" />Новый сотрудник</button>
        </>} />

      <div className="card mb-5 flex items-start gap-3 border-brand-200 bg-brand-50/60 p-4 text-sm dark:border-brand-400/20 dark:bg-brand-500/10">
        <Bot className="mt-0.5 size-5 shrink-0 text-brand-500" />
        <div>Блокировка учётной записи и принудительная смена пароля выполняются через <Link to="/chat" className="font-medium text-brand-700 underline dark:text-brand-300">бота безопасности</Link>:
          <code className="mx-1 rounded bg-white/70 px-1.5 dark:bg-black/30">/lock логин</code>,
          <code className="mx-1 rounded bg-white/70 px-1.5 dark:bg-black/30">/forcepwd логин</code> — нужна роль «Офицер безопасности» в TSL Auth.</div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex rounded-xl bg-slate-100 p-1 dark:bg-white/5">
          <button onClick={() => setTab("users")} className={clsx("rounded-lg px-3 py-1.5 text-sm font-medium", tab === "users" ? "bg-white shadow-sm dark:bg-white/10" : "text-slate-500")}>Сотрудники · {users.data.length}</button>
          <button onClick={() => setTab("requests")} className={clsx("flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium", tab === "requests" ? "bg-white shadow-sm dark:bg-white/10" : "text-slate-500")}>
            Заявки {pending > 0 && <span className="grid min-w-5 place-items-center rounded-full bg-rose-500 px-1 text-[11px] text-white">{pending}</span>}
          </button>
        </div>
        {tab === "users" && <>
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
            <input className="input pl-9" placeholder="Поиск по имени, логину, почте" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="input w-auto" value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
            <option value="">Все роли</option>
            {roles.map((r) => <option key={r.name} value={r.name}>{r.title}</option>)}
          </select>
        </>}
      </div>

      {tab === "users" ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((u) => (
            <div key={u.id} className="card relative p-4">
              <div className="flex items-start gap-3">
                <Avatar name={u.displayName || u.userName} size={44} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-semibold">{u.displayName || u.userName}</span>
                    {u.id === me.id && <span className="chip bg-slate-100 text-slate-600 dark:bg-white/10 dark:text-slate-300">вы</span>}
                  </div>
                  <div className="truncate text-sm text-slate-500">@{u.userName}{u.email && ` · ${u.email}`}</div>
                </div>
                <button className="btn-ghost p-1.5" onClick={() => setMenu(menu === u.id ? null : u.id)} aria-label="Действия"><MoreHorizontal className="size-4" /></button>
                {menu === u.id && (
                  <div className="card animate-rise absolute right-3 top-12 z-20 w-60 bg-white p-1 shadow-xl dark:bg-[#141b36]" onMouseLeave={() => setMenu(null)}>
                    {[
                      { icon: Pencil, label: "Изменить и роли", act: () => open({ edit: u }, u) },
                      { icon: KeyRound, label: "Выдать временный пароль", act: async () => {
                        const r = await run(() => api<{ password: string }>(`/api/users/${u.id}/temporary-password`, { method: "POST" }));
                        if (r) { setSecret({ label: `Временный пароль для ${u.userName}`, value: r.password }); setModal({ edit: u }); users.reload(); }
                      } },
                      { icon: Mail, label: "Ссылка-приглашение", act: async () => {
                        const r = await run(() => api<{ link: string }>(`/api/users/${u.id}/invite`, { method: "POST" }));
                        if (r) { setSecret({ label: `Приглашение для ${u.userName}`, value: r.link }); setModal({ edit: u }); }
                      } },
                      { icon: Trash2, label: u.createdByThisApp ? "Удалить" : "Отвязать от приложения", danger: true, act: async () => {
                        if (confirm(`${u.createdByThisApp ? "Удалить" : "Отвязать"} ${u.userName}?`) && await run(() => api(`/api/users/${u.id}`, { method: "DELETE" }), "Готово")) users.reload();
                      } }
                    ].map((a) => (
                      <button key={a.label} onClick={() => { setMenu(null); a.act(); }}
                        className={clsx("flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-white/5", a.danger && "text-rose-600")}>
                        <a.icon className="size-4" />{a.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {u.roles.length === 0 && <span className="text-xs text-slate-400">без ролей</span>}
                {u.roles.map((r) => <span key={r} className="chip bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200"><ShieldCheck className="size-3" />{roleTitle(r)}</span>)}
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5 text-xs">
                {!u.isActive && <span className="chip bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300">заблокирован</span>}
                {u.mustChangePassword && <span className="chip bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300">сменить пароль</span>}
                {!u.hasPassword && <span className="chip bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300">ждёт приглашения</span>}
                {!u.createdByThisApp && <span className="chip bg-slate-100 text-slate-600 dark:bg-white/10 dark:text-slate-400">общая учётка</span>}
              </div>
            </div>
          ))}
          {list.length === 0 && <div className="card md:col-span-2 xl:col-span-3"><Empty icon={<UserRoundPlus className="size-6" />} title="Никого не нашли" /></div>}
        </div>
      ) : (
        <div className="card overflow-hidden">
          {!requests.data ? <PageLoader /> : requests.data.length === 0
            ? <Empty icon={<Check className="size-6" />} title="Новых заявок нет" text="Сотрудники могут запросить роль при регистрации на странице входа TSL Auth." />
            : <div className="divide-y divide-slate-100 dark:divide-white/5">
                {requests.data.map((r) => (
                  <div key={r.id} className="flex flex-wrap items-center gap-4 p-4">
                    <Avatar name={r.userName ?? "?"} size={40} />
                    <div className="min-w-0 flex-1">
                      <div className="font-medium">{r.userName} <span className="text-sm font-normal text-slate-500">{r.email}</span></div>
                      <div className="text-sm text-slate-500">просит роль <b className="text-slate-700 dark:text-slate-200">{r.roleTitle}</b> · {relTime(r.createdAt)}</div>
                      {r.comment && <div className="mt-1 text-sm italic text-slate-500">«{r.comment}»</div>}
                    </div>
                    <button className="btn-outline text-rose-600" disabled={busy}
                      onClick={async () => { if (await run(() => api(`/api/users/requests/${r.id}/reject`, { method: "POST", json: {} }), "Отклонено")) requests.reload(); }}>
                      <X className="size-4" />Отклонить
                    </button>
                    <button className="btn-success" disabled={busy}
                      onClick={async () => { if (await run(() => api(`/api/users/requests/${r.id}/approve`, { method: "POST", json: {} }), "Роль выдана")) { requests.reload(); users.reload(); } }}>
                      <Check className="size-4" />Одобрить
                    </button>
                  </div>
                ))}
              </div>}
        </div>
      )}

      <Modal open={modal === "create"} onClose={() => setModal(null)} title="Новый сотрудник" wide
        footer={secret ? <button className="btn-primary" onClick={() => setModal(null)}>Готово</button> : <>
          <button className="btn-ghost" onClick={() => setModal(null)}>Отмена</button>
          <button className="btn-primary" disabled={busy || !form.userName.trim()} onClick={create}>Создать</button>
        </>}>
        {secret ? <Secret {...secret} /> : (
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div><label className="label">Логин</label><input className="input" value={form.userName} onChange={(e) => setForm({ ...form, userName: e.target.value })} placeholder="ivanov" autoFocus /></div>
              <div><label className="label">Email</label><input className="input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="ivanov@corp.local" /></div>
            </div>
            <div><label className="label">ФИО</label><input className="input" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} placeholder="Иванов Иван" /></div>
            <div><span className="label">Роли</span><RolePicker roles={roles} value={form.roles} onChange={(v) => setForm({ ...form, roles: v })} /></div>
            <label className="flex items-center gap-3 rounded-xl border border-slate-200 p-3 text-sm dark:border-white/10">
              <input type="checkbox" className="size-4 accent-brand-500" checked={form.invite} onChange={(e) => setForm({ ...form, invite: e.target.checked })} />
              Выдать ссылку-приглашение вместо временного пароля
            </label>
          </div>
        )}
      </Modal>

      <Modal open={modal === "link"} onClose={() => setModal(null)} title="Добавить существующего" wide
        footer={<><button className="btn-ghost" onClick={() => setModal(null)}>Отмена</button>
          <button className="btn-primary" disabled={busy || !form.login.trim() || form.roles.length === 0} onClick={link}>Выдать роли</button></>}>
        <div className="space-y-4">
          <p className="text-sm text-slate-500">Сотрудник уже есть в TSL Auth (например, работает в другой системе). Укажите точный логин или email.</p>
          <div><label className="label">Логин или email</label><input className="input" value={form.login} onChange={(e) => setForm({ ...form, login: e.target.value })} autoFocus /></div>
          <div><span className="label">Роли</span><RolePicker roles={roles} value={form.roles} onChange={(v) => setForm({ ...form, roles: v })} /></div>
        </div>
      </Modal>

      {typeof modal === "object" && modal && (
        <Modal open onClose={() => setModal(null)} title={modal.edit.displayName || modal.edit.userName} wide
          footer={<><button className="btn-ghost" onClick={() => setModal(null)}>Закрыть</button>
            <button className="btn-primary" disabled={busy} onClick={() => saveEdit(modal.edit)}>Сохранить</button></>}>
          <div className="space-y-4">
            {secret && <Secret {...secret} />}
            {modal.edit.createdByThisApp ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <div><label className="label">Логин</label><input className="input" value={form.userName} onChange={(e) => setForm({ ...form, userName: e.target.value })} /></div>
                <div><label className="label">Email</label><input className="input" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
                <div className="sm:col-span-2"><label className="label">ФИО</label><input className="input" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></div>
              </div>
            ) : (
              <p className="rounded-xl bg-slate-50 p-3 text-sm text-slate-500 dark:bg-white/5">Учётная запись общая (создана не этим приложением): здесь можно менять только роли документооборота. Профиль — в <a className="underline" href={cabinetUrl("Admin")} target="_blank">TSL Auth</a>.</p>
            )}
            <div><span className="label">Роли в документообороте</span><RolePicker roles={roles} value={form.roles} onChange={(v) => setForm({ ...form, roles: v })} /></div>
          </div>
        </Modal>
      )}
    </>
  );
}
