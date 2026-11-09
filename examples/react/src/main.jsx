import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider } from "react-oidc-context";
import { WebStorageStateStore } from "oidc-client-ts";
import App from "./App.jsx";

const origin = window.location.origin;

// Public client (auth.mode: app, client_type: public). oidc-client-ts
// использует Authorization Code + PKCE (S256) — Guard требует PKCE.
const oidcConfig = {
  authority: import.meta.env.VITE_OIDC_AUTHORITY,
  client_id: import.meta.env.VITE_OIDC_CLIENT_ID,
  // Должны совпадать с redirect_uris / post_logout_redirect_uris в YAML.
  redirect_uri: `${origin}/callback`,
  post_logout_redirect_uri: `${origin}/`,
  scope: "openid profile email groups",
  // Токены живут в sessionStorage вкладки (по умолчанию). Обновление —
  // через refresh token, который Guard выдаёт клиенту.
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  automaticSilentRenew: true,
  // Убираем ?code=&state= из адреса после входа.
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, "/");
  },
};

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <AuthProvider {...oidcConfig}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
