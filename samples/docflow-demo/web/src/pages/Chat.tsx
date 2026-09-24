import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import clsx from "clsx";
import { Bot, Check, Copy, Eye, EyeOff, ExternalLink, Send, ShieldAlert, Trash2 } from "lucide-react";
import { api, type ChatButton, type ChatMessage } from "../api";
import { cabinetUrl } from "../auth";
import { useSession } from "../session";
import { Avatar, Spinner, useToast } from "../components/ui";

/** Мини-разметка сообщений бота: **жирный** и `код`. */
function Rich({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  text.split("\n").forEach((line, li) => {
    if (li) parts.push(<br key={`br${li}`} />);
    line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).forEach((p, i) => {
      if (p.startsWith("**")) parts.push(<b key={`${li}-${i}`}>{p.slice(2, -2)}</b>);
      else if (p.startsWith("`")) parts.push(<code key={`${li}-${i}`} className="rounded bg-black/5 px-1 py-0.5 font-mono text-[0.85em] dark:bg-white/10">{p.slice(1, -1)}</code>);
      else parts.push(<Fragment key={`${li}-${i}`}>{p}</Fragment>);
    });
  });
  return <>{parts}</>;
}

function SecretValue({ value }: { value: string }) {
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-2 flex items-center gap-1 rounded-lg bg-white/70 p-1 pl-3 dark:bg-black/30">
      <code className="flex-1 font-mono text-sm">{shown ? value : "•".repeat(12)}</code>
      <button className="btn-ghost p-1.5" onClick={() => setShown((s) => !s)} aria-label="Показать">{shown ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</button>
      <button className="btn-ghost p-1.5" onClick={() => { navigator.clipboard.writeText(value); setCopied(true); }} aria-label="Копировать">{copied ? <Check className="size-4" /> : <Copy className="size-4" />}</button>
    </div>
  );
}

const quick = ["/help", "/whoami", "/reset", "/forcepwd", "/lock"];

export default function ChatPage() {
  const { me } = useSession();
  const toast = useToast();
  const [messages, setMessages] = useState<ChatMessage[] | null>(null);
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => { api<ChatMessage[]>("/api/chat/history").then(setMessages).catch((e) => { toast("error", e.message); setMessages([]); }); }, [toast]);
  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, sending]);

  const send = async (value: string) => {
    const t = value.trim();
    if (!t || sending) return;
    setText("");
    setSending(true);
    const optimistic: ChatMessage = { id: `tmp-${Date.now()}`, from: "user", text: t, at: new Date().toISOString(), kind: "text", buttons: [] };
    setMessages((m) => [...(m ?? []), optimistic]);
    try {
      const r = await api<ChatMessage[]>("/api/chat/messages", { method: "POST", json: { text: t } });
      setMessages((m) => [...(m ?? []).filter((x) => x.id !== optimistic.id), ...r]);
    } catch (e) {
      setMessages((m) => (m ?? []).filter((x) => x.id !== optimistic.id));
      toast("error", e instanceof Error ? e.message : String(e));
      setText(t);
    } finally { setSending(false); }
  };

  const clear = async () => {
    await api("/api/chat/history", { method: "DELETE" }).catch(() => {});
    setMessages(await api<ChatMessage[]>("/api/chat/history"));
  };

  const click = (b: ChatButton) => b.url ? window.open(b.url, "_blank", "noopener") : b.send && send(b.send);
  const tone: Record<string, string> = {
    success: "border-emerald-200 bg-emerald-50 dark:border-emerald-400/20 dark:bg-emerald-500/10",
    error: "border-rose-200 bg-rose-50 dark:border-rose-400/20 dark:bg-rose-500/10",
    confirm: "border-amber-200 bg-amber-50 dark:border-amber-400/20 dark:bg-amber-500/10",
    secret: "border-emerald-200 bg-emerald-50 dark:border-emerald-400/20 dark:bg-emerald-500/10"
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
      <div className="card flex h-[calc(100dvh-13rem)] min-h-[480px] flex-col overflow-hidden lg:h-[calc(100dvh-8rem)]">
        <div className="flex items-center gap-3 border-b border-slate-100 px-5 py-3 dark:border-white/10">
          <div className="relative grid size-10 place-items-center rounded-full bg-gradient-to-br from-brand-500 to-violet-600 text-white shadow-md shadow-brand-500/30">
            <Bot className="size-5" />
            <span className="absolute bottom-0 right-0 size-3 rounded-full border-2 border-white bg-emerald-500 dark:border-[#0b1020]" />
          </div>
          <div className="flex-1">
            <div className="font-semibold">Бот безопасности</div>
            <div className="text-xs text-slate-500">подключён к TSL Auth · провайдер docflow-chat</div>
          </div>
          <button className="btn-ghost p-2" onClick={clear} title="Очистить историю" aria-label="Очистить"><Trash2 className="size-4" /></button>
        </div>

        <div className="scrollbar-thin flex-1 space-y-4 overflow-y-auto bg-gradient-to-b from-slate-50/50 to-transparent px-4 py-5 sm:px-6 dark:from-white/[0.01]">
          {!messages && <div className="grid h-full place-items-center"><Spinner /></div>}
          {messages?.map((m) => m.from === "user" ? (
            <div key={m.id} className="animate-rise flex justify-end gap-2">
              <div className="max-w-[80%] rounded-2xl rounded-br-sm bg-gradient-to-br from-brand-500 to-violet-600 px-4 py-2.5 text-sm text-white shadow-md shadow-brand-500/20">{m.text}</div>
              <Avatar name={me.displayName} size={32} />
            </div>
          ) : (
            <div key={m.id} className="animate-rise flex gap-2">
              <div className="grid size-8 shrink-0 place-items-center rounded-full bg-gradient-to-br from-brand-500 to-violet-600 text-white"><Bot className="size-4" /></div>
              <div className="max-w-[85%]">
                <div className={clsx("rounded-2xl rounded-bl-sm border px-4 py-2.5 text-sm leading-relaxed", tone[m.kind] ?? "border-slate-200 bg-white dark:border-white/10 dark:bg-white/5")}>
                  {m.kind === "confirm" && <ShieldAlert className="mb-1 size-4 text-amber-600" />}
                  <Rich text={m.text} />
                  {m.secret && <SecretValue value={m.secret} />}
                </div>
                {m.buttons.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {m.buttons.map((b) => (
                      <button key={b.label} onClick={() => click(b)} disabled={sending}
                        className={clsx("btn py-1.5 text-xs", b.style === "danger" ? "bg-rose-600 text-white hover:bg-rose-500" : b.style === "primary" ? "btn-primary" : "btn-outline")}>
                        {b.label}{b.url && <ExternalLink className="size-3" />}
                      </button>
                    ))}
                  </div>
                )}
                <div className="mt-1 text-[11px] text-slate-400">{new Date(m.at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })}</div>
              </div>
            </div>
          ))}
          {sending && (
            <div className="flex gap-2">
              <div className="grid size-8 place-items-center rounded-full bg-gradient-to-br from-brand-500 to-violet-600 text-white"><Bot className="size-4" /></div>
              <div className="flex items-center gap-1 rounded-2xl border border-slate-200 bg-white px-4 py-3 dark:border-white/10 dark:bg-white/5">
                {[0, 1, 2].map((i) => <span key={i} className="size-1.5 animate-bounce rounded-full bg-slate-400" style={{ animationDelay: `${i * 120}ms` }} />)}
              </div>
            </div>
          )}
          <div ref={end} />
        </div>

        <div className="border-t border-slate-100 p-3 dark:border-white/10">
          <div className="scrollbar-thin mb-2 flex gap-1.5 overflow-x-auto">
            {quick.map((q) => <button key={q} onClick={() => send(q)} disabled={sending} className="chip shrink-0 border border-slate-200 py-1 font-mono text-slate-600 hover:border-brand-300 hover:text-brand-600 dark:border-white/10 dark:text-slate-300">{q}</button>)}
          </div>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); send(text); }}>
            <input className="input" value={text} onChange={(e) => setText(e.target.value)} placeholder="Команда или сообщение, например: заблокируй petrov" maxLength={500} />
            <button className="btn-primary px-4" disabled={sending || !text.trim()} aria-label="Отправить"><Send className="size-4" /></button>
          </form>
        </div>
      </div>

      <aside className="space-y-4">
        <div className="card p-5 text-sm">
          <div className="mb-3 font-semibold">Как начать</div>
          <ol className="space-y-3">
            {[
              <>Откройте <a className="font-medium text-brand-600 underline dark:text-brand-300" href={cabinetUrl("Account/Messenger")} target="_blank" rel="noopener">личный кабинет TSL Auth</a> и получите код привязки.</>,
              <>Отправьте боту <code className="rounded bg-slate-100 px-1 dark:bg-white/10">/link КОД</code>.</>,
              <>Готово: сброс пароля, блокировка и смена пароля — прямо из чата.</>
            ].map((s, i) => (
              <li key={i} className="flex gap-3"><span className="grid size-6 shrink-0 place-items-center rounded-full bg-brand-100 text-xs font-bold text-brand-700 dark:bg-brand-500/20 dark:text-brand-200">{i + 1}</span><span>{s}</span></li>
            ))}
          </ol>
        </div>
        {(
          <div className="card p-5 text-sm">
            <div className="mb-2 font-semibold">Офицер безопасности</div>
            <p className="mb-3 text-slate-500">С ролью <b>security-officer</b> в TSL Auth можно действовать над другими сотрудниками:</p>
            <div className="space-y-1.5 font-mono text-xs">
              {["/lock логин", "/unlock логин", "/forcepwd логин"].map((c) => (
                <button key={c} onClick={() => setText(c.replace("логин", ""))} className="block w-full rounded-lg bg-slate-100 px-3 py-2 text-left hover:bg-brand-50 dark:bg-white/5 dark:hover:bg-brand-500/10">{c}</button>
              ))}
            </div>
          </div>
        )}
        <div className="card p-5 text-xs text-slate-500">
          Все действия бота фиксируются в журнале безопасности TSL Auth и попадают в ленту событий <code>security.alert</code>.
        </div>
      </aside>
    </div>
  );
}
