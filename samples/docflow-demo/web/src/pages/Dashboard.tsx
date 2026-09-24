import { Link } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ArrowUpRight, CheckCircle2, ClipboardCheck, Clock3, FileText, Hourglass, History, RefreshCw, XCircle } from "lucide-react";
import { cabinetUrl, userManager } from "../auth";
import clsx from "clsx";
import { api, type DocSummary, type Status } from "../api";
import { useSession } from "../session";
import { ErrorBox, PageHeader, PageLoader, relTime, statusMeta, useLoad } from "../components/ui";

type Dash = {
  byStatus: Record<Status, number>; total: number; mine: number; tasks: number; inReview: number; avgApprovalHours: number;
  byType: { type: string; count: number }[];
  weeks: { week: string; created: number; approved: number }[];
  recent: { at: string; actorName: string; action: string; details: string | null; docId: string; number: string; title: string }[];
};

function Stat({ icon: Icon, label, value, hint, tone }: { icon: typeof FileText; label: string; value: string | number; hint?: string; tone: string }) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-500 dark:text-slate-400">{label}</span>
        <span className={clsx("grid size-9 place-items-center rounded-xl", tone)}><Icon className="size-[18px]" /></span>
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-tight">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export default function Dashboard() {
  const { me, can } = useSession();
  const dash = useLoad(() => can("dashboard.view") ? api<Dash>("/api/dashboard") : Promise.resolve(null));
  const tasks = useLoad(() => can("documents.view") ? api<DocSummary[]>("/api/documents?scope=tasks") : Promise.resolve([]));
  // В справочнике ФИО хранится как «Фамилия Имя»: здороваемся по имени.
  const parts = me.displayName.split(" ").filter(Boolean);
  const first = parts[1] ?? parts[0];
  const hour = new Date().getHours();
  const hello = hour < 6 ? "Доброй ночи" : hour < 12 ? "Доброе утро" : hour < 18 ? "Добрый день" : "Добрый вечер";

  if (!can("documents.view")) return <NoRoles hello={`${hello}, ${first}!`} />;
  if (dash.error) return <ErrorBox text={dash.error} />;
  if (dash.data === null && can("dashboard.view")) return <PageLoader />;
  const d = dash.data;
  const total = d ? Object.values(d.byStatus).reduce((a, b) => a + b, 0) || 1 : 1;

  return (
    <>
      <PageHeader title={`${hello}, ${first}!`} subtitle="Сводка по документам и вашим задачам" />

      {d && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Stat icon={FileText} label="Всего документов" value={d.total} hint={`из них ваших — ${d.mine}`} tone="bg-brand-100 text-brand-600 dark:bg-brand-500/15 dark:text-brand-300" />
          <Stat icon={ClipboardCheck} label="Ждут вашего решения" value={d.tasks} tone="bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-300" />
          <Stat icon={Clock3} label="На согласовании" value={d.inReview} tone="bg-sky-100 text-sky-600 dark:bg-sky-500/15 dark:text-sky-300" />
          <Stat icon={CheckCircle2} label="Среднее время утверждения" value={d.avgApprovalHours ? `${d.avgApprovalHours < 1 ? "<1" : Math.round(d.avgApprovalHours)} ч` : "—"}
            hint={`утверждено — ${d.byStatus.Approved}`} tone="bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-300" />
        </div>
      )}

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        {d && (
          <div className="card min-w-0 p-5 lg:col-span-2">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
              <div className="font-semibold">Динамика за 8 недель</div>
              <div className="flex gap-4 text-xs text-slate-500">
                <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-brand-500" />Создано</span>
                <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-emerald-500" />Утверждено</span>
              </div>
            </div>
            <div className="h-64">
              <ResponsiveContainer>
                <AreaChart data={d.weeks} margin={{ left: -20, right: 8, top: 8 }}>
                  <defs>
                    <linearGradient id="gc" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#6366f1" stopOpacity={0.35} /><stop offset="1" stopColor="#6366f1" stopOpacity={0} /></linearGradient>
                    <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#10b981" stopOpacity={0.3} /><stop offset="1" stopColor="#10b981" stopOpacity={0} /></linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="currentColor" className="text-slate-200 dark:text-white/10" vertical={false} />
                  <XAxis dataKey="week" tick={{ fontSize: 12, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ borderRadius: 12, border: "none", boxShadow: "0 10px 30px rgb(0 0 0 / .15)", fontSize: 13 }} />
                  <Area type="monotone" dataKey="created" name="Создано" stroke="#6366f1" strokeWidth={2.5} fill="url(#gc)" />
                  <Area type="monotone" dataKey="approved" name="Утверждено" stroke="#10b981" strokeWidth={2.5} fill="url(#ga)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {d && (
          <div className="card p-5">
            <div className="mb-4 font-semibold">По статусам</div>
            <div className="mb-5 flex h-3 overflow-hidden rounded-full bg-slate-100 dark:bg-white/5">
              {(Object.keys(statusMeta) as Status[]).map((s) => d.byStatus[s] > 0 && (
                <div key={s} className={statusMeta[s].dot} style={{ width: `${(d.byStatus[s] / total) * 100}%` }} title={statusMeta[s].label} />
              ))}
            </div>
            <div className="space-y-2.5">
              {(Object.keys(statusMeta) as Status[]).map((s) => (
                <Link key={s} to={`/documents?status=${s}`} className="flex items-center justify-between rounded-lg px-1 text-sm hover:text-brand-600">
                  <span className="flex items-center gap-2"><span className={clsx("size-2.5 rounded-full", statusMeta[s].dot)} />{statusMeta[s].label}</span>
                  <span className="font-medium tabular-nums">{d.byStatus[s]}</span>
                </Link>
              ))}
            </div>
            <div className="mt-6 mb-3 font-semibold">По типам</div>
            <div className="space-y-2">
              {d.byType.map((t) => (
                <div key={t.type} className="text-sm">
                  <div className="mb-1 flex justify-between"><span className="text-slate-600 dark:text-slate-300">{t.type}</span><span className="tabular-nums">{t.count}</span></div>
                  <div className="h-1.5 rounded-full bg-slate-100 dark:bg-white/5">
                    <div className="h-1.5 rounded-full bg-gradient-to-r from-brand-500 to-violet-500" style={{ width: `${d.total ? (t.count / d.total) * 100 : 0}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="card min-w-0 p-5 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <div className="font-semibold">Ждут вашего решения</div>
            <Link to="/tasks" className="text-sm text-brand-600 hover:underline dark:text-brand-300">Все задачи</Link>
          </div>
          {!tasks.data ? <PageLoader /> : tasks.data.length === 0
            ? <div className="py-8 text-center text-sm text-slate-500">Задач нет — всё согласовано 🎉</div>
            : <div className="divide-y divide-slate-100 dark:divide-white/5">
                {tasks.data.slice(0, 6).map((t) => (
                  <Link key={t.id} to={`/documents/${t.id}`} className="group flex items-center gap-4 py-3">
                    <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-300"><FileText className="size-5" /></div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium group-hover:text-brand-600">{t.title}</div>
                      <div className="text-xs text-slate-500">{t.number} · {t.type} · от {t.authorName}</div>
                    </div>
                    <span className="chip bg-amber-100 text-amber-800 dark:bg-amber-400/15 dark:text-amber-300">{t.currentStep?.kind === "Approve" ? "утвердить" : "согласовать"}</span>
                    <ArrowUpRight className="size-4 text-slate-400 group-hover:text-brand-500" />
                  </Link>
                ))}
              </div>}
        </div>

        {d && (
          <div className="card p-5">
            <div className="mb-3 flex items-center gap-2 font-semibold"><History className="size-4" />Последние события</div>
            <ol className="relative space-y-4 border-l border-slate-200 pl-4 dark:border-white/10">
              {d.recent.map((r, i) => (
                <li key={i} className="text-sm">
                  <span className="absolute -left-[5px] mt-1.5 size-2.5 rounded-full border-2 border-white bg-brand-500 dark:border-[#0b1020]" />
                  <div><b className="font-medium">{r.actorName}</b> · {r.action.toLowerCase()}</div>
                  <Link to={`/documents/${r.docId}`} className="block truncate text-slate-500 hover:text-brand-600">{r.number} «{r.title}»</Link>
                  <div className="text-xs text-slate-400">{relTime(r.at)}</div>
                </li>
              ))}
              {d.recent.length === 0 && <li className="text-sm text-slate-500">Событий пока нет</li>}
            </ol>
          </div>
        )}
      </div>
    </>
  );
}


type MyRequest = { role: string; roleTitle: string; status: "pending" | "approved" | "rejected"; createdAt: string; decisionComment: string | null };

/**
 * Экран пользователя без ролей в документообороте — обычно сразу после саморегистрации.
 * Показывает его заявки; после одобрения нужен новый токен (роли приходят в нём), поэтому
 * «Обновить права» заново проходит вход — сессия TSL Auth уже есть, пароль не спрашивается.
 */
function NoRoles({ hello }: { hello: string }) {
  const requests = useLoad(() => api<MyRequest[]>("/api/me/requests"));
  const list = requests.data ?? [];
  const pending = list.filter((r) => r.status === "pending");
  const approved = list.some((r) => r.status === "approved");
  const refresh = () => userManager.signinRedirect({ state: "/" });
  const meta = {
    pending: { icon: Hourglass, cls: "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300", label: "на рассмотрении" },
    approved: { icon: CheckCircle2, cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300", label: "одобрена" },
    rejected: { icon: XCircle, cls: "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300", label: "отклонена" }
  } as const;
  return (
    <>
      <PageHeader title={hello} />
      <div className="card mx-auto max-w-2xl p-8 text-center">
        <div className="mx-auto mb-4 grid size-16 place-items-center rounded-2xl bg-gradient-to-br from-amber-400 to-orange-500 text-white shadow-lg shadow-amber-500/30">
          <Hourglass className="size-7" />
        </div>
        <h2 className="text-xl font-semibold">
          {approved ? "Заявка одобрена — обновите права" : pending.length ? "Заявка на доступ на рассмотрении" : "У вас пока нет доступа к документообороту"}
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm text-slate-500 dark:text-slate-400">
          {approved
            ? "Администратор выдал роль. Нажмите «Обновить права», чтобы получить её в этом сеансе."
            : pending.length
              ? "Администратор документооборота рассмотрит заявку. Когда роль выдадут, нажмите «Обновить права»."
              : "Попросите администратора выдать роль или запросите её: выйдите и нажмите «Зарегистрироваться» — либо обратитесь к администратору."}
        </p>
        {list.length > 0 && (
          <div className="mx-auto mt-6 max-w-md space-y-2 text-left">
            {list.map((r, i) => {
              const m = meta[r.status] ?? meta.pending;
              return (
                <div key={i} className="flex items-center gap-3 rounded-xl border border-slate-200 p-3 dark:border-white/10">
                  <span className={clsx("grid size-9 place-items-center rounded-lg", m.cls)}><m.icon className="size-4" /></span>
                  <div className="min-w-0 flex-1">
                    <div className="font-medium">{r.roleTitle}</div>
                    <div className="text-xs text-slate-500">заявка от {relTime(r.createdAt)}{r.decisionComment && ` · «${r.decisionComment}»`}</div>
                  </div>
                  <span className={clsx("chip", m.cls)}>{m.label}</span>
                </div>
              );
            })}
          </div>
        )}
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button className="btn-primary" onClick={refresh}><RefreshCw className="size-4" />Обновить права</button>
          <button className="btn-outline" onClick={requests.reload}>Проверить статус</button>
          <a className="btn-ghost" href={cabinetUrl("Account")} target="_blank" rel="noopener">Личный кабинет TSL Auth</a>
        </div>
      </div>
    </>
  );
}
