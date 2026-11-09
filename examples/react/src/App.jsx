import { useEffect, useState } from "react";
import { useAuth, hasAuthParams } from "react-oidc-context";

export default function App() {
  const auth = useAuth();
  const [apiResult, setApiResult] = useState(null);

  // Автоматический вход: если сессии нет — сразу на страницу Guard.
  // Уберите этот эффект, если нужна публичная главная страница.
  useEffect(() => {
    if (!hasAuthParams() && !auth.isAuthenticated && !auth.activeNavigator && !auth.isLoading && !auth.error) {
      auth.signinRedirect();
    }
  }, [auth]);

  if (auth.isLoading || auth.activeNavigator) return <p>Вход…</p>;
  if (auth.error) return <p>Ошибка входа: {auth.error.message}</p>;
  if (!auth.isAuthenticated) return <button onClick={() => auth.signinRedirect()}>Войти</button>;

  const profile = auth.user.profile;

  async function callApi() {
    // Access token в заголовке Authorization. API обязано проверить
    // подпись, iss, aud и exp (см. examples/express).
    const res = await fetch(`${import.meta.env.VITE_API_URL}/api/me`, {
      headers: { Authorization: `Bearer ${auth.user.access_token}` },
    });
    setApiResult(await res.json());
  }

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 560, margin: "3rem auto" }}>
      <h1>Привет, {profile.given_name || profile.email}</h1>
      <p>sub: {profile.sub}</p>
      <p>группы: {(profile.groups || []).join(", ") || "—"}</p>
      <p>
        <a href={`${import.meta.env.VITE_OIDC_AUTHORITY}account`}>Мой аккаунт и Passkeys</a>
      </p>
      <button onClick={callApi}>Вызвать API</button>{" "}
      <button onClick={() => auth.signoutRedirect()}>Выйти</button>
      {apiResult && <pre>{JSON.stringify(apiResult, null, 2)}</pre>}
    </main>
  );
}
