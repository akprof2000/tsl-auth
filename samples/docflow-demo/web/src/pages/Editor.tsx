import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import clsx from "clsx";
import { ArrowDown, ArrowLeft, ArrowUp, Plus, Save, Send, Trash2, UserRound, UsersRound } from "lucide-react";
import { api, type DirUser, type DocFull, type Role } from "../api";
import { useSession } from "../session";
import { ErrorBox, PageHeader, PageLoader, useAction, useLoad } from "../components/ui";

type StepDraft = { kind: "Review" | "Approve"; mode: "role" | "user"; role: string; userId: string };

export default function EditorPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { roles } = useSession();
  const { busy, run } = useAction();
  const types = useLoad(() => api<string[]>("/api/documents/types"));
  const directory = useLoad(() => api<DirUser[]>("/api/directory"));
  const existing = useLoad(() => id ? api<DocFull>(`/api/documents/${id}`) : Promise.resolve(null), [id]);

  const [title, setTitle] = useState("");
  const [type, setType] = useState("Служебная записка");
  const [content, setContent] = useState("");
  const [steps, setSteps] = useState<StepDraft[]>([]);

  // Кто может быть исполнителем шага: роли, в которых есть нужное разрешение (из матрицы TSL Auth).
  const rolesFor = (kind: StepDraft["kind"]) => roles.filter((r: Role) => r.permissions.includes(kind === "Approve" ? "documents.approve" : "documents.review"));
  const usersFor = (kind: StepDraft["kind"]) => (directory.data ?? []).filter((u) => u.roles.some((r) => rolesFor(kind).some((x) => x.name === r)));

  useEffect(() => {
    const d = existing.data;
    if (d) {
      setTitle(d.title); setType(d.type); setContent(d.content);
      setSteps(d.steps.map((s) => ({ kind: s.kind, mode: s.assigneeUserId ? "user" : "role", role: s.assigneeRole ?? "", userId: s.assigneeUserId ?? "" })));
    } else if (!id && roles.length) {
      setSteps([
        { kind: "Review", mode: "role", role: rolesFor("Review")[0]?.name ?? "", userId: "" },
        { kind: "Approve", mode: "role", role: rolesFor("Approve")[0]?.name ?? "", userId: "" }
      ]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [existing.data, roles]);

  if (existing.error) return <ErrorBox text={existing.error} />;
  if (id && !existing.data) return <PageLoader />;

  const patch = (i: number, p: Partial<StepDraft>) => setSteps((s) => s.map((x, j) => j === i ? { ...x, ...p } : x));
  const move = (i: number, dir: -1 | 1) => setSteps((s) => { const c = [...s]; [c[i], c[i + dir]] = [c[i + dir]!, c[i]!]; return c; });

  const save = async (submit: boolean) => {
    const body = {
      title, type, content,
      steps: steps.map((s) => ({ kind: s.kind, assigneeRole: s.mode === "role" ? s.role : null, assigneeUserId: s.mode === "user" ? s.userId || null : null }))
    };
    const doc = await run(async () => {
      const saved = id
        ? await api<DocFull>(`/api/documents/${id}`, { method: "PUT", json: body })
        : await api<DocFull>("/api/documents", { method: "POST", json: body });
      return submit ? api<DocFull>(`/api/documents/${saved.id}/submit`, { method: "POST" }) : saved;
    }, submit ? "Отправлено на согласование" : "Сохранено");
    if (doc) navigate(`/documents/${doc.id}`, { replace: true });
  };

  const valid = title.trim().length > 0 && steps.every((s) => s.mode === "role" ? s.role : s.userId);

  return (
    <>
      <button onClick={() => navigate(-1)} className="btn-ghost -ml-2 mb-3 px-2 text-slate-500"><ArrowLeft className="size-4" />Назад</button>
      <PageHeader title={id ? "Редактирование" : "Новый документ"} subtitle={existing.data?.number}
        actions={<>
          <button className="btn-outline" disabled={busy || !title.trim()} onClick={() => save(false)}><Save className="size-4" />Сохранить черновик</button>
          <button className="btn-primary" disabled={busy || !valid || steps.length === 0} onClick={() => save(true)}><Send className="size-4" />Отправить</button>
        </>} />

      <div className="grid gap-6 lg:grid-cols-[1fr_400px]">
        <div className="card space-y-5 p-6">
          <div>
            <label className="label" htmlFor="title">Название</label>
            <input id="title" className="input text-base" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="О проведении инвентаризации" maxLength={200} autoFocus />
          </div>
          <div>
            <span className="label">Тип документа</span>
            <div className="flex flex-wrap gap-2">
              {(types.data ?? [type]).map((t) => (
                <button key={t} type="button" onClick={() => setType(t)}
                  className={clsx("rounded-xl border px-3 py-1.5 text-sm transition", t === type ? "border-brand-400 bg-brand-50 text-brand-700 dark:border-brand-400/50 dark:bg-brand-500/15 dark:text-brand-200" : "border-slate-200 hover:border-slate-300 dark:border-white/10")}>
                  {t}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="label" htmlFor="content">Текст</label>
            <textarea id="content" className="input min-h-72 leading-relaxed" value={content} onChange={(e) => setContent(e.target.value)} placeholder="Содержание документа…" />
          </div>
        </div>

        <div className="card h-fit p-5">
          <div className="mb-1 font-semibold">Маршрут согласования</div>
          <p className="mb-4 text-xs text-slate-500">Шаги идут по порядку. Исполнитель — конкретный сотрудник или любой с ролью. Роли настраиваются в TSL Auth.</p>
          <div className="space-y-3">
            {steps.map((s, i) => (
              <div key={i} className="rounded-xl border border-slate-200 p-3 dark:border-white/10">
                <div className="mb-2 flex items-center gap-2">
                  <span className="grid size-6 place-items-center rounded-full bg-brand-500 text-xs font-bold text-white">{i + 1}</span>
                  <select className="input w-auto flex-1 py-1.5" value={s.kind} onChange={(e) => patch(i, { kind: e.target.value as StepDraft["kind"], role: rolesFor(e.target.value as StepDraft["kind"])[0]?.name ?? "", userId: "" })}>
                    <option value="Review">Согласование</option>
                    <option value="Approve">Утверждение</option>
                  </select>
                  <button className="btn-ghost p-1.5" disabled={i === 0} onClick={() => move(i, -1)} aria-label="Выше"><ArrowUp className="size-4" /></button>
                  <button className="btn-ghost p-1.5" disabled={i === steps.length - 1} onClick={() => move(i, 1)} aria-label="Ниже"><ArrowDown className="size-4" /></button>
                  <button className="btn-ghost p-1.5 text-rose-500" onClick={() => setSteps((x) => x.filter((_, j) => j !== i))} aria-label="Удалить"><Trash2 className="size-4" /></button>
                </div>
                <div className="mb-2 flex rounded-lg bg-slate-100 p-0.5 text-xs dark:bg-white/5">
                  {([["role", "Любой с ролью", UsersRound], ["user", "Сотрудник", UserRound]] as const).map(([m, l, Icon]) => (
                    <button key={m} onClick={() => patch(i, { mode: m })} className={clsx("flex flex-1 items-center justify-center gap-1.5 rounded-md py-1.5 font-medium", s.mode === m ? "bg-white shadow-sm dark:bg-white/10" : "text-slate-500")}>
                      <Icon className="size-3.5" />{l}
                    </button>
                  ))}
                </div>
                {s.mode === "role" ? (
                  <select className="input py-1.5" value={s.role} onChange={(e) => patch(i, { role: e.target.value })}>
                    <option value="">— выберите роль —</option>
                    {rolesFor(s.kind).map((r) => <option key={r.name} value={r.name}>{r.title}</option>)}
                  </select>
                ) : (
                  <select className="input py-1.5" value={s.userId} onChange={(e) => patch(i, { userId: e.target.value })}>
                    <option value="">— выберите сотрудника —</option>
                    {usersFor(s.kind).map((u) => <option key={u.id} value={u.id}>{u.name} ({u.userName})</option>)}
                  </select>
                )}
              </div>
            ))}
          </div>
          <button className="btn-outline mt-3 w-full border-dashed" disabled={steps.length >= 10}
            onClick={() => setSteps((s) => [...s, { kind: "Review", mode: "role", role: rolesFor("Review")[0]?.name ?? "", userId: "" }])}>
            <Plus className="size-4" />Добавить шаг
          </button>
        </div>
      </div>
    </>
  );
}
