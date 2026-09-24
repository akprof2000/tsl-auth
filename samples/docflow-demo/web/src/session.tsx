import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, type Me, type Role } from "./api";
import { userManager } from "./auth";

type Session = {
  me: Me;
  roles: Role[];
  can: (permission: string) => boolean;
  roleTitle: (name: string) => string;
  logout: () => void;
};

const Ctx = createContext<Session | null>(null);
export const useSession = () => useContext(Ctx)!;

/**
 * Профиль и права берутся из API (которое читает их из JWT), названия ролей — из матрицы TSL Auth.
 * Интерфейс лишь прячет недоступные действия; настоящую проверку делает API по тем же разрешениям.
 */
export function SessionProvider({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [me, roles] = await Promise.all([api<Me>("/api/me"), api<Role[]>("/api/roles").catch(() => [] as Role[])]);
        setSession({
          me, roles,
          can: (p) => me.permissions.includes(p),
          roleTitle: (n) => roles.find((r) => r.name === n)?.title ?? n,
          logout: () => userManager.signoutRedirect().catch(() => userManager.removeUser().then(() => location.assign("/")))
        });
      } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    })();
  }, []);

  if (error) return (
    <div className="grid h-full place-items-center p-6 text-center">
      <div className="card max-w-md p-8">
        <div className="mb-2 text-lg font-semibold">Не удалось загрузить профиль</div>
        <p className="mb-5 text-sm text-slate-500">{error}</p>
        <button className="btn-primary" onClick={() => location.reload()}>Повторить</button>
      </div>
    </div>
  );
  if (!session) return <>{fallback}</>;
  return <Ctx.Provider value={session}>{children}</Ctx.Provider>;
}
