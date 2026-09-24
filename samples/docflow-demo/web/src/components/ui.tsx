import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import clsx from "clsx";
import { CheckCircle2, CircleAlert, Info, Loader2, X } from "lucide-react";
import type { Status } from "../api";

// ---------- Статусы ----------

export const statusMeta: Record<Status, { label: string; cls: string; dot: string }> = {
  Draft: { label: "Черновик", cls: "bg-slate-100 text-slate-700 dark:bg-white/10 dark:text-slate-300", dot: "bg-slate-400" },
  InReview: { label: "На согласовании", cls: "bg-amber-100 text-amber-800 dark:bg-amber-400/15 dark:text-amber-300", dot: "bg-amber-500" },
  Approved: { label: "Утверждён", cls: "bg-emerald-100 text-emerald-800 dark:bg-emerald-400/15 dark:text-emerald-300", dot: "bg-emerald-500" },
  Rejected: { label: "Отклонён", cls: "bg-rose-100 text-rose-800 dark:bg-rose-400/15 dark:text-rose-300", dot: "bg-rose-500" },
  Archived: { label: "В архиве", cls: "bg-indigo-100 text-indigo-800 dark:bg-indigo-400/15 dark:text-indigo-300", dot: "bg-indigo-400" }
};

export function StatusBadge({ status }: { status: Status }) {
  const m = statusMeta[status];
  return <span className={clsx("chip", m.cls)}><span className={clsx("size-1.5 rounded-full", m.dot)} />{m.label}</span>;
}

// ---------- Аватар с инициалами ----------

const palette = ["from-indigo-500 to-violet-500", "from-sky-500 to-cyan-500", "from-emerald-500 to-teal-500", "from-amber-500 to-orange-500", "from-rose-500 to-pink-500", "from-fuchsia-500 to-purple-500"];

export function Avatar({ name, size = 32 }: { name: string; size?: number }) {
  const initials = name.split(/\s+/).filter(Boolean).slice(0, 2).map((s) => s[0]!.toUpperCase()).join("") || "?";
  const hash = [...name].reduce((h, c) => (h * 31 + c.charCodeAt(0)) | 0, 0);
  return (
    <span style={{ width: size, height: size, fontSize: size * 0.38 }}
      className={clsx("inline-grid shrink-0 place-items-center rounded-full bg-gradient-to-br font-semibold text-white", palette[Math.abs(hash) % palette.length])}>
      {initials}
    </span>
  );
}

// ---------- Мелочи ----------

export const Spinner = ({ className }: { className?: string }) => <Loader2 className={clsx("size-5 animate-spin text-brand-500", className)} />;

export function PageLoader() {
  return <div className="grid h-64 place-items-center"><Spinner className="size-7" /></div>;
}

export function Empty({ icon, title, text, action }: { icon: ReactNode; title: string; text?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="grid size-14 place-items-center rounded-2xl bg-brand-50 text-brand-500 dark:bg-brand-500/10">{icon}</div>
      <div className="font-semibold">{title}</div>
      {text && <p className="max-w-sm text-sm text-slate-500 dark:text-slate-400">{text}</p>}
      {action}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export const fmtDate = (s: string | null | undefined, withTime = true) =>
  s ? new Date(s).toLocaleString("ru-RU", withTime ? { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" } : { day: "2-digit", month: "long", year: "numeric" }) : "—";

export function relTime(s: string) {
  const diff = (Date.now() - new Date(s).getTime()) / 1000;
  if (diff < 60) return "только что";
  if (diff < 3600) return `${Math.floor(diff / 60)} мин назад`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} ч назад`;
  return new Date(s).toLocaleDateString("ru-RU", { day: "numeric", month: "short" });
}

// ---------- Модальное окно ----------

export function Modal({ open, onClose, title, children, footer, wide }: {
  open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/40 p-0 backdrop-blur-sm sm:items-center sm:p-4" onMouseDown={onClose}>
      <div className={clsx("card animate-rise max-h-[92vh] w-full overflow-hidden rounded-b-none bg-white sm:rounded-2xl dark:bg-[#121831]", wide ? "sm:max-w-2xl" : "sm:max-w-md")}
        onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={title}>
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-white/10">
          <h2 className="font-semibold">{title}</h2>
          <button className="btn-ghost p-1.5" onClick={onClose} aria-label="Закрыть"><X className="size-4" /></button>
        </div>
        <div className="scrollbar-thin max-h-[65vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-slate-100 bg-slate-50/60 px-5 py-3 dark:border-white/10 dark:bg-white/[0.02]">{footer}</div>}
      </div>
    </div>
  );
}

// ---------- Уведомления (тосты) ----------

type Toast = { id: number; kind: "success" | "error" | "info"; text: string };
const ToastCtx = createContext<(kind: Toast["kind"], text: string) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-20 z-[60] flex flex-col items-center gap-2 px-4 sm:bottom-6 sm:items-end">
        {toasts.map((t) => (
          <div key={t.id} className="card animate-rise pointer-events-auto flex max-w-sm items-start gap-3 bg-white px-4 py-3 text-sm shadow-lg dark:bg-[#161d3a]">
            {t.kind === "success" ? <CheckCircle2 className="size-5 shrink-0 text-emerald-500" /> : t.kind === "error" ? <CircleAlert className="size-5 shrink-0 text-rose-500" /> : <Info className="size-5 shrink-0 text-brand-500" />}
            <span>{t.text}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** Выполнить действие с индикатором и тостом ошибки. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(async <T,>(fn: () => Promise<T>, success?: string): Promise<T | undefined> => {
    setBusy(true);
    try {
      const r = await fn();
      if (success) toast("success", success);
      return r;
    } catch (e) {
      toast("error", e instanceof Error ? e.message : String(e));
      return undefined;
    } finally { setBusy(false); }
  }, [toast]);
  return { busy, run };
}

/** Простая загрузка данных с перезагрузкой. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setError(null);
    load().then((d) => alive && setData(d)).catch((e) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, reload: () => setTick((t) => t + 1), setData };
}

export function ErrorBox({ text }: { text: string }) {
  return <div className="card flex items-center gap-3 border-rose-200 bg-rose-50 p-4 text-sm text-rose-800 dark:border-rose-400/20 dark:bg-rose-500/10 dark:text-rose-200"><CircleAlert className="size-5" />{text}</div>;
}
