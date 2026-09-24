import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { ChevronRight, FilePlus2, FileText, Inbox, Search } from "lucide-react";
import { api, type DocSummary, type Status } from "../api";
import { useSession } from "../session";
import { Avatar, Empty, ErrorBox, PageHeader, PageLoader, StatusBadge, relTime, statusMeta, useLoad } from "../components/ui";

const tabs: { key: string; label: string }[] = [
  { key: "", label: "Все" }, { key: "mine", label: "Мои" }, { key: "tasks", label: "Ждут меня" }
];

export default function DocumentsPage({ scope: fixedScope }: { scope?: "tasks" }) {
  const { can, roleTitle } = useSession();
  const [params, setParams] = useSearchParams();
  const scope = fixedScope ?? params.get("scope") ?? "";
  const status = params.get("status") ?? "";
  const [search, setSearch] = useState(params.get("q") ?? "");
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }); };

  const query = new URLSearchParams({ ...(scope && { scope }), ...(status && { status }), ...(params.get("q") && { search: params.get("q")! }) });
  const docs = useLoad(() => api<DocSummary[]>(`/api/documents?${query}`), [query.toString()]);

  return (
    <>
      <PageHeader
        title={fixedScope ? "Мои задачи" : "Документы"}
        subtitle={fixedScope ? "Документы, по которым ждут вашего согласования или утверждения" : "Реестр документов организации"}
        actions={can("documents.create") && <Link to="/documents/new" className="btn-primary"><FilePlus2 className="size-4" />Создать</Link>}
      />

      <div className="card mb-5 flex flex-col gap-3 p-3 md:flex-row md:items-center">
        {!fixedScope && (
          <div className="flex rounded-xl bg-slate-100 p-1 dark:bg-white/5">
            {tabs.map((t) => (
              <button key={t.key} onClick={() => set("scope", t.key)}
                className={clsx("rounded-lg px-3 py-1.5 text-sm font-medium transition", scope === t.key ? "bg-white shadow-sm dark:bg-white/10" : "text-slate-500 hover:text-slate-800 dark:hover:text-slate-200")}>
                {t.label}
              </button>
            ))}
          </div>
        )}
        <form className="relative flex-1" onSubmit={(e) => { e.preventDefault(); set("q", search.trim()); }}>
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
          <input className="input pl-9" placeholder="Поиск по номеру, названию, автору…" value={search} onChange={(e) => setSearch(e.target.value)}
            onBlur={() => set("q", search.trim())} />
        </form>
        <div className="scrollbar-thin flex gap-1.5 overflow-x-auto">
          <button onClick={() => set("status", "")} className={clsx("chip border py-1", !status ? "border-brand-300 bg-brand-50 text-brand-700 dark:border-brand-400/40 dark:bg-brand-500/15 dark:text-brand-200" : "border-slate-200 text-slate-500 dark:border-white/10")}>Любой статус</button>
          {(Object.keys(statusMeta) as Status[]).map((s) => (
            <button key={s} onClick={() => set("status", status === s ? "" : s)}
              className={clsx("chip border py-1", status === s ? "border-brand-300 bg-brand-50 text-brand-700 dark:border-brand-400/40 dark:bg-brand-500/15 dark:text-brand-200" : "border-slate-200 text-slate-500 dark:border-white/10")}>
              {statusMeta[s].label}
            </button>
          ))}
        </div>
      </div>

      {docs.error ? <ErrorBox text={docs.error} /> : !docs.data ? <PageLoader /> : docs.data.length === 0 ? (
        <div className="card">
          <Empty icon={fixedScope ? <Inbox className="size-6" /> : <FileText className="size-6" />}
            title={fixedScope ? "Задач нет" : "Документов не найдено"}
            text={fixedScope ? "Когда документ придёт вам на согласование, он появится здесь." : "Измените фильтры или создайте первый документ."}
            action={!fixedScope && can("documents.create") && <Link to="/documents/new" className="btn-primary">Создать документ</Link>} />
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="hidden grid-cols-[1fr_170px_150px_160px_110px_24px] gap-4 border-b border-slate-100 px-5 py-3 text-xs font-medium uppercase tracking-wide text-slate-500 md:grid dark:border-white/10">
            <span>Документ</span><span>Статус</span><span>Маршрут</span><span>Автор</span><span>Изменён</span><span />
          </div>
          <div className="divide-y divide-slate-100 dark:divide-white/5">
            {docs.data.map((d) => (
              <Link key={d.id} to={`/documents/${d.id}`}
                className="group grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-2 px-5 py-4 transition hover:bg-slate-50/80 md:grid-cols-[1fr_170px_150px_160px_110px_24px] dark:hover:bg-white/[0.03]">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium group-hover:text-brand-600 dark:group-hover:text-brand-300">{d.title}</span>
                    {d.myTask && <span className="chip bg-amber-100 text-amber-800 dark:bg-amber-400/15 dark:text-amber-300">ваш шаг</span>}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">{d.number} · {d.type} · v{d.version}</div>
                </div>
                <div className="justify-self-end md:justify-self-start"><StatusBadge status={d.status} /></div>
                <div className="col-span-2 md:col-span-1">
                  {d.stepsTotal > 0 ? (
                    <div>
                      <div className="flex gap-1">
                        {Array.from({ length: d.stepsTotal }).map((_, i) => (
                          <span key={i} className={clsx("h-1.5 flex-1 rounded-full", i < d.stepsDone ? "bg-emerald-500" : i === d.stepsDone && d.status === "InReview" ? "bg-amber-400" : d.status === "Rejected" && i === d.stepsDone ? "bg-rose-500" : "bg-slate-200 dark:bg-white/10")} />
                        ))}
                      </div>
                      <div className="mt-1 truncate text-xs text-slate-500">{d.stepsDone}/{d.stepsTotal}{d.currentStep && ` · ${roleTitle(d.currentStep.assignee)}`}</div>
                    </div>
                  ) : <span className="text-xs text-slate-400">без маршрута</span>}
                </div>
                <div className="hidden items-center gap-2 text-sm md:flex"><Avatar name={d.authorName} size={24} /><span className="truncate">{d.authorName}</span></div>
                <div className="hidden text-sm text-slate-500 md:block">{relTime(d.updatedAt)}</div>
                <ChevronRight className="hidden size-4 text-slate-300 group-hover:text-brand-500 md:block" />
              </Link>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
