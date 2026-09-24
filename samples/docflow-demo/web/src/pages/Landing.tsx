import { ArrowRight, FileCheck2, KeyRound, ShieldCheck, UserPlus, Users } from "lucide-react";
import { registerRedirect, userManager } from "../auth";

/** Экран до входа: вход только через TSL Auth — пароли приложение никогда не видит. */
export default function Landing() {
  const features = [
    { icon: FileCheck2, title: "Маршруты согласования", text: "Многошаговое согласование и утверждение, версии и история решений." },
    { icon: ShieldCheck, title: "Права из TSL Auth", text: "Роли и матрица разрешений настраиваются централизованно в TSL Auth." },
    { icon: Users, title: "Управление сотрудниками", text: "Создание пользователей и назначение ролей прямо в приложении." },
    { icon: KeyRound, title: "Бот безопасности", text: "Сброс пароля, блокировка учётки и принудительная смена пароля из чата." }
  ];
  return (
    <div className="relative min-h-full overflow-hidden">
      <div className="pointer-events-none absolute -left-40 -top-40 size-[520px] rounded-full bg-brand-500/25 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-40 -right-20 size-[480px] rounded-full bg-fuchsia-500/20 blur-3xl" />
      <div className="relative mx-auto flex min-h-full max-w-6xl flex-col px-6 py-10">
        <header className="flex items-center gap-3">
          <img src="/icon.svg" className="size-9" alt="" />
          <span className="font-semibold">Документооборот</span>
          <span className="chip ml-2 bg-brand-100 text-brand-700 dark:bg-brand-500/15 dark:text-brand-300">демо TSL Auth</span>
        </header>
        <main className="grid flex-1 items-center gap-12 py-12 lg:grid-cols-[1.1fr_1fr]">
          <div className="animate-rise">
            <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-5xl">
              Документы, согласования и доступ —{" "}
              <span className="bg-gradient-to-r from-brand-500 to-fuchsia-500 bg-clip-text text-transparent">в одном окне</span>
            </h1>
            <p className="mt-5 max-w-xl text-lg text-slate-600 dark:text-slate-300">
              Вход через единый сервис TSL Auth. Работает как приложение на телефоне и компьютере.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <button className="btn-primary px-6 py-3 text-base" onClick={() => userManager.signinRedirect({ state: location.pathname })}>
                Войти через TSL Auth <ArrowRight className="size-4" />
              </button>
              <button className="btn-outline px-6 py-3 text-base" onClick={() => registerRedirect()}>
                <UserPlus className="size-4" />Зарегистрироваться
              </button>
            </div>
            <p className="mt-3 max-w-xl text-sm text-slate-500 dark:text-slate-400">
              Новый сотрудник регистрируется сам и выбирает роль — её выдают после одобрения администратором.
            </p>
            <p className="mt-4 text-xs text-slate-500">Демо-учётки: ivanova, petrov, sidorova, kozlov, admin-doc · пароль Demo-Passw0rd!</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {features.map((f, i) => (
              <div key={f.title} className="card animate-rise p-5" style={{ animationDelay: `${i * 70}ms` }}>
                <div className="mb-3 grid size-10 place-items-center rounded-xl bg-gradient-to-br from-brand-500 to-violet-600 text-white shadow-md shadow-brand-500/30">
                  <f.icon className="size-5" />
                </div>
                <div className="font-semibold">{f.title}</div>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{f.text}</p>
              </div>
            ))}
          </div>
        </main>
      </div>
    </div>
  );
}
