import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import clsx from "clsx";
import { Bell, Bot, ClipboardCheck, FilePlus2, FileText, LayoutDashboard, LogOut, Moon, Sun, UserCog, Users } from "lucide-react";
import { api, type Notice } from "../api";
import { useSession } from "../session";
import { Avatar, relTime } from "./ui";

function useTheme() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch { /* приватный режим */ }
  }, [dark]);
  return [dark, () => setDark((d) => !d)] as const;
}

/** Колокольчик: уведомления из API, опрос раз в 20 секунд. */
function Notifications() {
  const [items, setItems] = useState<Notice[]>([]);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const load = () => api<Notice[]>("/api/notifications").then(setItems).catch(() => {});
  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    addEventListener("mousedown", close);
    return () => { clearInterval(t); removeEventListener("mousedown", close); };
  }, []);
  const unread = items.filter((n) => !n.readAt).length;
  const toggle = async () => {
    setOpen((o) => !o);
    if (!open && unread) { await api("/api/notifications/read", { method: "POST" }).catch(() => {}); setTimeout(load, 1500); }
  };
  const dot: Record<string, string> = { task: "bg-amber-500", success: "bg-emerald-500", danger: "bg-rose-500", info: "bg-brand-500" };
  return (
    <div className="relative" ref={ref}>
      <button className="btn-ghost relative p-2" onClick={toggle} aria-label="Уведомления">
        <Bell className="size-5" />
        {unread > 0 && <span className="absolute right-1 top-1 grid min-w-4 place-items-center rounded-full bg-rose-500 px-1 text-[10px] font-bold text-white">{unread}</span>}
      </button>
      {open && (
        <div className="card animate-rise absolute right-0 z-40 mt-2 w-[min(92vw,360px)] overflow-hidden bg-white shadow-xl dark:bg-[#141b36]">
          <div className="border-b border-slate-100 px-4 py-3 text-sm font-semibold dark:border-white/10">Уведомления</div>
          <div className="scrollbar-thin max-h-96 overflow-y-auto">
            {items.length === 0 && <div className="px-4 py-8 text-center text-sm text-slate-500">Пока пусто</div>}
            {items.map((n) => (
              <button key={n.id} onClick={() => { setOpen(false); if (n.link) navigate(n.link); }}
                className={clsx("flex w-full gap-3 px-4 py-3 text-left text-sm hover:bg-slate-50 dark:hover:bg-white/5", !n.readAt && "bg-brand-50/60 dark:bg-brand-500/5")}>
                <span className={clsx("mt-1.5 size-2 shrink-0 rounded-full", dot[n.kind] ?? dot.info)} />
                <span className="flex-1">
                  <span className="block">{n.text}</span>
                  <span className="text-xs text-slate-500">{relTime(n.createdAt)}</span>
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Layout() {
  const { me, can, logout, roleTitle } = useSession();
  const [dark, toggleTheme] = useTheme();
  const location = useLocation();

  const nav = [
    { to: "/", icon: LayoutDashboard, label: "Обзор", show: can("dashboard.view") || can("documents.view"), end: true },
    { to: "/documents", icon: FileText, label: "Документы", show: can("documents.view") },
    { to: "/tasks", icon: ClipboardCheck, label: "Мои задачи", show: can("documents.review") || can("documents.approve") },
    { to: "/users", icon: Users, label: "Пользователи", show: can("users.manage") },
    { to: "/chat", icon: Bot, label: "Бот безопасности", show: true },
    { to: "/profile", icon: UserCog, label: "Профиль", show: true }
  ].filter((n) => n.show);

  const mobile = nav.filter((n) => ["/", "/documents", "/tasks", "/chat", "/profile"].includes(n.to)).slice(0, 5);

  return (
    <div className="flex min-h-full">
      {/* Боковая панель — на широких экранах */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-slate-200/70 bg-white/70 px-3 py-5 backdrop-blur lg:flex dark:border-white/10 dark:bg-white/[0.02]">
        <Link to="/" className="mb-6 flex items-center gap-2.5 px-3">
          <img src="/icon.svg" className="size-8" alt="" />
          <div className="leading-tight">
            <div className="font-semibold">Документооборот</div>
            <div className="text-xs text-slate-500">на TSL Auth</div>
          </div>
        </Link>
        {can("documents.create") && (
          <Link to="/documents/new" className="btn-primary mx-1 mb-5 py-2.5"><FilePlus2 className="size-4" />Новый документ</Link>
        )}
        <nav className="flex flex-col gap-1">
          {nav.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}
              className={({ isActive }) => clsx("flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition",
                isActive ? "bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-white/5")}>
              <n.icon className="size-[18px]" />{n.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto rounded-2xl border border-slate-200/70 p-3 dark:border-white/10">
          <div className="flex items-center gap-3">
            <Avatar name={me.displayName} size={36} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{me.displayName}</div>
              <div className="truncate text-xs text-slate-500">{me.roles.map(roleTitle).join(", ") || "без ролей"}</div>
            </div>
          </div>
          <div className="mt-3 flex gap-1">
            <button className="btn-ghost flex-1 py-1.5 text-xs" onClick={toggleTheme}>{dark ? <Sun className="size-4" /> : <Moon className="size-4" />}Тема</button>
            <button className="btn-ghost flex-1 py-1.5 text-xs" onClick={logout}><LogOut className="size-4" />Выйти</button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-slate-200/70 bg-white/70 px-4 backdrop-blur-xl sm:px-6 dark:border-white/10 dark:bg-[#0b1020]/70">
          <Link to="/" className="flex items-center gap-2 lg:hidden"><img src="/icon.svg" className="size-7" alt="" /><span className="font-semibold">Документы</span></Link>
          <div className="ml-auto flex items-center gap-1">
            {can("documents.create") && <Link to="/documents/new" className="btn-primary px-3 lg:hidden" aria-label="Новый документ"><FilePlus2 className="size-4" /></Link>}
            <button className="btn-ghost p-2 lg:hidden" onClick={toggleTheme} aria-label="Тема">{dark ? <Sun className="size-5" /> : <Moon className="size-5" />}</button>
            <Notifications />
          </div>
        </header>
        <main key={location.pathname} className="animate-rise mx-auto w-full max-w-7xl flex-1 px-4 pb-28 pt-6 sm:px-6 lg:pb-10">
          <Outlet />
        </main>
      </div>

      {/* Нижняя навигация — на телефоне */}
      <nav className="fixed inset-x-0 bottom-0 z-40 grid border-t border-slate-200/70 bg-white/85 pb-[env(safe-area-inset-bottom)] backdrop-blur-xl lg:hidden dark:border-white/10 dark:bg-[#0b1020]/85"
        style={{ gridTemplateColumns: `repeat(${mobile.length}, 1fr)` }}>
        {mobile.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end}
            className={({ isActive }) => clsx("flex flex-col items-center gap-0.5 py-2 text-[11px] font-medium", isActive ? "text-brand-600 dark:text-brand-300" : "text-slate-500")}>
            <n.icon className="size-5" />{n.label.split(" ")[0]}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
