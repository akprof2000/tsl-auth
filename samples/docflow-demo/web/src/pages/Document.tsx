import { useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import clsx from "clsx";
import {
  Archive, ArrowLeft, Check, CheckCircle2, Circle, Clock3, Download, FileText, GitCommitVertical, History, MessageSquare,
  Paperclip, Pencil, Send, Trash2, Upload, XCircle
} from "lucide-react";
import { api, download, type DocFull, type Step } from "../api";
import { useSession } from "../session";
import { Avatar, ErrorBox, Modal, PageLoader, StatusBadge, fmtDate, relTime, useAction, useLoad } from "../components/ui";

const size = (b: number) => b < 1024 ? `${b} Б` : b < 1048576 ? `${(b / 1024).toFixed(0)} КБ` : `${(b / 1048576).toFixed(1)} МБ`;

function StepIcon({ step }: { step: Step }) {
  if (step.status === "Done") return <CheckCircle2 className="size-5 text-emerald-500" />;
  if (step.status === "Rejected") return <XCircle className="size-5 text-rose-500" />;
  if (step.status === "Active") return <span className="relative grid size-5 place-items-center"><span className="absolute size-5 animate-ping rounded-full bg-amber-400/40" /><Clock3 className="size-5 text-amber-500" /></span>;
  return <Circle className="size-5 text-slate-300 dark:text-slate-600" />;
}

export default function DocumentPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { me, roleTitle } = useSession();
  const doc = useLoad(() => api<DocFull>(`/api/documents/${id}`), [id]);
  const { busy, run } = useAction();
  const [tab, setTab] = useState<"comments" | "history" | "versions">("comments");
  const [decision, setDecision] = useState<null | boolean>(null);
  const [comment, setComment] = useState("");
  const [note, setNote] = useState("");
  const file = useRef<HTMLInputElement>(null);

  if (doc.error) return <ErrorBox text={doc.error} />;
  if (!doc.data) return <PageLoader />;
  const d = doc.data;
  const update = (r: DocFull | undefined) => r && doc.setData(r);
  const active = d.steps.find((s) => s.status === "Active");

  const decide = async () => {
    const r = await run(() => api<DocFull>(`/api/documents/${d.id}/decide`, { method: "POST", json: { approve: decision, comment: comment || null } }),
      decision ? "Решение принято" : "Документ отклонён");
    if (r) { update(r); setDecision(null); setComment(""); }
  };

  const upload = async (f: File) => {
    const form = new FormData();
    form.append("file", f);
    update(await run(() => api<DocFull>(`/api/documents/${d.id}/attachments`, { method: "POST", body: form }), "Файл загружен"));
  };

  return (
    <>
      <button onClick={() => navigate(-1)} className="btn-ghost -ml-2 mb-3 px-2 text-slate-500"><ArrowLeft className="size-4" />Назад</button>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2 text-sm text-slate-500">
            <span className="font-mono">{d.number}</span><span>·</span><span>{d.type}</span><span>·</span><span>версия {d.version}</span>
            <StatusBadge status={d.status} />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{d.title}</h1>
          <div className="mt-2 flex items-center gap-2 text-sm text-slate-500">
            <Avatar name={d.authorName} size={22} />{d.authorName} · создан {fmtDate(d.createdAt)}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {d.can.edit && <Link to={`/documents/${d.id}/edit`} className="btn-outline"><Pencil className="size-4" />Изменить</Link>}
          {d.can.submit && (
            <button className="btn-primary" disabled={busy || d.steps.length === 0} title={d.steps.length === 0 ? "Добавьте маршрут" : undefined}
              onClick={async () => update(await run(() => api<DocFull>(`/api/documents/${d.id}/submit`, { method: "POST" }), "Отправлено на согласование"))}>
              <Send className="size-4" />На согласование
            </button>
          )}
          {d.can.archive && (
            <button className="btn-outline" disabled={busy}
              onClick={async () => update(await run(() => api<DocFull>(`/api/documents/${d.id}/archive`, { method: "POST" }), "Перемещён в архив"))}>
              <Archive className="size-4" />В архив
            </button>
          )}
          {d.can.delete && (
            <button className="btn-ghost text-rose-600" disabled={busy}
              onClick={async () => { if (confirm("Удалить черновик?")) { await run(() => api(`/api/documents/${d.id}`, { method: "DELETE" }), "Черновик удалён"); navigate("/documents"); } }}>
              <Trash2 className="size-4" />
            </button>
          )}
        </div>
      </div>

      {d.can.decide && active && (
        <div className="card mb-6 flex flex-col gap-4 border-amber-200 bg-gradient-to-r from-amber-50 to-white p-5 sm:flex-row sm:items-center dark:border-amber-400/20 dark:from-amber-500/10 dark:to-transparent">
          <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-amber-500 text-white shadow-lg shadow-amber-500/30"><Clock3 className="size-5" /></div>
          <div className="flex-1">
            <div className="font-semibold">Документ ждёт вашего решения</div>
            <div className="text-sm text-slate-600 dark:text-slate-300">Шаг {active.order}: {active.kind === "Approve" ? "утверждение" : "согласование"}</div>
          </div>
          <div className="flex gap-2">
            <button className="btn-outline text-rose-600" onClick={() => setDecision(false)}><XCircle className="size-4" />Отклонить</button>
            <button className="btn-success" onClick={() => setDecision(true)}><Check className="size-4" />{active.kind === "Approve" ? "Утвердить" : "Согласовать"}</button>
          </div>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_340px]">
        <div className="space-y-6">
          <div className="card p-6">
            <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-500"><FileText className="size-4" />Содержание</div>
            <div className="whitespace-pre-wrap leading-relaxed">{d.content || <span className="text-slate-400">Текст не заполнен</span>}</div>
          </div>

          <div className="card p-6">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-500"><Paperclip className="size-4" />Вложения · {d.attachments.length}</div>
              {d.can.attach && (
                <>
                  <input ref={file} type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = ""; }} />
                  <button className="btn-outline py-1.5" disabled={busy} onClick={() => file.current?.click()}><Upload className="size-4" />Загрузить</button>
                </>
              )}
            </div>
            {d.attachments.length === 0 ? <div className="text-sm text-slate-400">Файлов нет</div> : (
              <div className="grid gap-2 sm:grid-cols-2">
                {d.attachments.map((a) => (
                  <div key={a.id} className="group flex items-center gap-3 rounded-xl border border-slate-200 p-3 dark:border-white/10">
                    <div className="grid size-10 place-items-center rounded-lg bg-brand-50 text-xs font-bold uppercase text-brand-600 dark:bg-brand-500/10 dark:text-brand-300">
                      {a.fileName.split(".").pop()?.slice(0, 4)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{a.fileName}</div>
                      <div className="text-xs text-slate-500">{size(a.size)} · {a.uploadedByName}</div>
                    </div>
                    <button className="btn-ghost p-1.5" onClick={() => run(() => download(`/api/documents/${d.id}/attachments/${a.id}`, a.fileName))} aria-label="Скачать"><Download className="size-4" /></button>
                    {d.can.attach && (
                      <button className="btn-ghost p-1.5 text-rose-500 opacity-0 group-hover:opacity-100" aria-label="Удалить"
                        onClick={async () => { await run(() => api(`/api/documents/${d.id}/attachments/${a.id}`, { method: "DELETE" }), "Удалено"); doc.reload(); }}>
                        <Trash2 className="size-4" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card p-2">
            <div className="flex gap-1 p-1">
              {([["comments", `Обсуждение · ${d.comments.length}`, MessageSquare], ["history", "История", History], ["versions", `Версии · ${d.versions.length}`, GitCommitVertical]] as const).map(([k, l, Icon]) => (
                <button key={k} onClick={() => setTab(k)} className={clsx("flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium", tab === k ? "bg-slate-100 dark:bg-white/10" : "text-slate-500")}>
                  <Icon className="size-4" />{l}
                </button>
              ))}
            </div>
            <div className="p-4">
              {tab === "comments" && (
                <>
                  <div className="space-y-4">
                    {d.comments.map((c) => (
                      <div key={c.id} className={clsx("flex gap-3", c.authorId === me.id && "flex-row-reverse")}>
                        <Avatar name={c.authorName} size={32} />
                        <div className={clsx("max-w-[80%] rounded-2xl px-4 py-2.5 text-sm", c.authorId === me.id ? "rounded-tr-sm bg-brand-500 text-white" : "rounded-tl-sm bg-slate-100 dark:bg-white/5")}>
                          <div className={clsx("mb-0.5 text-xs", c.authorId === me.id ? "text-brand-100" : "text-slate-500")}>{c.authorName} · {relTime(c.createdAt)}</div>
                          <div className="whitespace-pre-wrap">{c.text}</div>
                        </div>
                      </div>
                    ))}
                    {d.comments.length === 0 && <div className="py-4 text-center text-sm text-slate-400">Комментариев пока нет</div>}
                  </div>
                  <form className="mt-4 flex gap-2" onSubmit={async (e) => {
                    e.preventDefault();
                    if (!note.trim()) return;
                    const r = await run(() => api<DocFull>(`/api/documents/${d.id}/comments`, { method: "POST", json: { text: note } }));
                    if (r) { update(r); setNote(""); }
                  }}>
                    <input className="input" placeholder="Написать комментарий…" value={note} onChange={(e) => setNote(e.target.value)} />
                    <button className="btn-primary" disabled={busy || !note.trim()} aria-label="Отправить"><Send className="size-4" /></button>
                  </form>
                </>
              )}
              {tab === "history" && (
                <ol className="space-y-3">
                  {d.history.map((h, i) => (
                    <li key={i} className="flex gap-3 text-sm">
                      <span className="mt-1.5 size-2 shrink-0 rounded-full bg-brand-400" />
                      <div className="flex-1"><b className="font-medium">{h.actorName}</b> — {h.action}{h.details && <span className="text-slate-500">: {h.details}</span>}</div>
                      <span className="shrink-0 text-xs text-slate-400">{fmtDate(h.at)}</span>
                    </li>
                  ))}
                </ol>
              )}
              {tab === "versions" && (
                d.versions.length === 0 ? <div className="py-4 text-center text-sm text-slate-400">Версия фиксируется при отправке на согласование</div> : (
                  <div className="space-y-3">
                    {d.versions.map((v) => (
                      <details key={v.id} className="group rounded-xl border border-slate-200 p-3 dark:border-white/10">
                        <summary className="flex cursor-pointer list-none items-center gap-3 text-sm">
                          <span className="chip bg-brand-100 text-brand-700 dark:bg-brand-500/15 dark:text-brand-300">v{v.number}</span>
                          <span className="flex-1 font-medium">{v.title}</span>
                          <span className="text-xs text-slate-500">{v.createdByName} · {fmtDate(v.createdAt)}</span>
                        </summary>
                        {v.note && <div className="mt-2 text-xs text-slate-500">{v.note}</div>}
                        <div className="mt-2 whitespace-pre-wrap rounded-lg bg-slate-50 p-3 text-sm dark:bg-white/5">{v.content}</div>
                      </details>
                    ))}
                  </div>
                )
              )}
            </div>
          </div>
        </div>

        <aside className="space-y-6">
          <div className="card p-5">
            <div className="mb-4 font-semibold">Маршрут согласования</div>
            {d.steps.length === 0 ? <div className="text-sm text-slate-400">Маршрут не задан</div> : (
              <ol className="relative">
                {d.steps.map((s, i) => (
                  <li key={s.id} className="relative flex gap-3 pb-5 last:pb-0">
                    {i < d.steps.length - 1 && <span className={clsx("absolute left-[9px] top-6 h-[calc(100%-20px)] w-0.5", s.status === "Done" ? "bg-emerald-400" : "bg-slate-200 dark:bg-white/10")} />}
                    <StepIcon step={s} />
                    <div className="min-w-0 flex-1 text-sm">
                      <div className="font-medium">{s.kind === "Approve" ? "Утверждение" : "Согласование"}</div>
                      <div className="text-slate-500">{s.assigneeName ?? `любой: ${roleTitle(s.assigneeRole ?? "")}`}</div>
                      {s.decidedByName && <div className="mt-1 text-xs text-slate-500">{s.decidedByName} · {fmtDate(s.decidedAt)}</div>}
                      {s.comment && <div className={clsx("mt-1.5 rounded-lg px-2.5 py-1.5 text-xs", s.status === "Rejected" ? "bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300" : "bg-slate-50 dark:bg-white/5")}>«{s.comment}»</div>}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
          <div className="card space-y-3 p-5 text-sm">
            <div className="flex justify-between"><span className="text-slate-500">Создан</span><span>{fmtDate(d.createdAt)}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Изменён</span><span>{fmtDate(d.updatedAt)}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Версия</span><span>{d.version}</span></div>
          </div>
        </aside>
      </div>

      <Modal open={decision !== null} onClose={() => setDecision(null)} title={decision ? (active?.kind === "Approve" ? "Утвердить документ" : "Согласовать документ") : "Отклонить документ"}
        footer={<>
          <button className="btn-ghost" onClick={() => setDecision(null)}>Отмена</button>
          <button className={decision ? "btn-success" : "btn-danger"} disabled={busy || (!decision && !comment.trim())} onClick={decide}>
            {decision ? "Подтвердить" : "Отклонить"}
          </button>
        </>}>
        <label className="label">{decision ? "Комментарий (необязательно)" : "Причина отклонения"}</label>
        <textarea className="input min-h-28" autoFocus value={comment} onChange={(e) => setComment(e.target.value)}
          placeholder={decision ? "Например: согласовано без замечаний" : "Что нужно доработать?"} />
      </Modal>
    </>
  );
}
