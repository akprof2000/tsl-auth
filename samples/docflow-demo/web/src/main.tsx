import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes, useNavigate } from "react-router-dom";
import type { User } from "oidc-client-ts";
import "./index.css";
import { userManager } from "./auth";
import { SessionProvider } from "./session";
import { PageLoader, ToastProvider } from "./components/ui";
import Layout from "./components/Layout";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import DocumentsPage from "./pages/Documents";
import DocumentPage from "./pages/Document";
import EditorPage from "./pages/Editor";
import UsersPage from "./pages/Users";
import ChatPage from "./pages/Chat";
import ProfilePage from "./pages/Profile";

// Обмен code на токены должен произойти ровно один раз (StrictMode вызывает эффекты дважды).
let callback: Promise<User> | null = null;

/** Возврат из TSL Auth после входа: обмениваем code на токены и уходим туда, откуда пришли. */
function Callback() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    (callback ??= userManager.signinRedirectCallback())
      .then((u) => navigate(typeof u.state === "string" && u.state.startsWith("/") ? u.state : "/", { replace: true }))
      .catch((e) => setError(String(e?.message ?? e)));
  }, [navigate]);
  return error
    ? <div className="grid h-full place-items-center p-6"><div className="card max-w-md p-6 text-sm"><b>Ошибка входа.</b> {error}<div className="mt-4"><a className="btn-primary" href="/">На главную</a></div></div></div>
    : <PageLoader />;
}

function App() {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  useEffect(() => {
    userManager.getUser().then(setUser);
    const onLoaded = (u: User) => setUser(u);
    const onGone = () => setUser(null);
    userManager.events.addUserLoaded(onLoaded);
    userManager.events.addUserUnloaded(onGone);
    userManager.events.addSilentRenewError(onGone);
    return () => {
      userManager.events.removeUserLoaded(onLoaded);
      userManager.events.removeUserUnloaded(onGone);
      userManager.events.removeSilentRenewError(onGone);
    };
  }, []);

  if (location.pathname === "/callback") return <Routes><Route path="/callback" element={<Callback />} /></Routes>;
  if (user === undefined) return <PageLoader />;
  if (!user || user.expired && !user.refresh_token) return <Landing />;

  return (
    <SessionProvider fallback={<PageLoader />}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="documents" element={<DocumentsPage />} />
          <Route path="tasks" element={<DocumentsPage scope="tasks" />} />
          <Route path="documents/new" element={<EditorPage />} />
          <Route path="documents/:id" element={<DocumentPage />} />
          <Route path="documents/:id/edit" element={<EditorPage />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="chat" element={<ChatPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="*" element={<Dashboard />} />
        </Route>
      </Routes>
    </SessionProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <App />
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>
);
