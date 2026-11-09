# Подключение React-приложения (SPA)

SPA — это *public client*: секрета нет, вход идёт через Authorization Code + PKCE прямо из браузера. Пример лежит в [examples/react](../examples/react).

## 1. Описать приложение в Guard

Добавьте элемент в `applications` в `config/guard.yml`:

```yaml
applications:
  - name: spa
    domain: spa.example.com
    upstream: {host: spa, port: 80}    # контейнер со статикой (nginx, caddy, serve)
    auth:
      mode: app
      client_type: public
      redirect_uris: [https://spa.example.com/callback]
      post_logout_redirect_uris: [https://spa.example.com/]
      scopes: [openid, profile, email, groups]
```

`guard-sync` создаст в Rauthy клиента `spa` со следующими настройками:
- PKCE `S256` обязателен;
- разрешённые origins (CORS для token endpoint): `https://spa.example.com`;
- токены подписываются `RS256` (можно сменить через `signing_alg`), access token живёт 30 минут (`access_token_seconds`), есть refresh token.

## 2. Настроить клиент

```bash
cd examples/react
cp .env.example .env      # VITE_OIDC_AUTHORITY, VITE_OIDC_CLIENT_ID, VITE_API_URL
npm install
npm run build             # dist/ отдаётся upstream-контейнером
```

Основные настройки ([src/main.jsx](../examples/react/src/main.jsx)):

```jsx
<AuthProvider
  authority="https://auth.example.com/auth/v1/"
  client_id="spa"
  redirect_uri={`${location.origin}/callback`}
  post_logout_redirect_uri={`${location.origin}/`}
  scope="openid profile email groups"
  onSigninCallback={() => window.history.replaceState({}, document.title, "/")}
>
```

- `authority` — это issuer Guard. `oidc-client-ts` сам прочитает discovery и JWKS.
- `redirect_uri` и `post_logout_redirect_uri` должны **точно** совпадать с `guard.yml`.
- Маршрут `/callback` должен отдавать `index.html`. Для SPA с history-роутингом настройте fallback в веб-сервере.

## 3. Вызов API

```js
fetch("https://api.example.com/api/me", {
  headers: { Authorization: `Bearer ${auth.user.access_token}` },
});
```

API **обязано** проверить подпись, `iss`, `aud` и `exp` токена (см. [integration-express.md](integration-express.md#2-api-с-проверкой-bearer-токена)). Для токенов этого SPA `aud` = `spa`.

## 4. Passkeys и аккаунт

Ссылка на кабинет пользователя: `https://auth.example.com/auth/v1/account`. Там добавляются и удаляются Passkeys и меняется пароль. Вход по Passkey доступен прямо на странице входа Guard, в приложении для этого ничего делать не нужно.

## Если что-то не работает

| Симптом | Причина |
|---|---|
| `invalid redirect_uri` на странице входа | URI в коде и в `guard.yml` различаются (схема, порт, завершающий слэш) |
| CORS-ошибка на `/token` | origin SPA не совпадает с `allowed_origins` (по умолчанию `https://<domain>`) |
| Бесконечный редирект после входа | не задан `onSigninCallback`, параметры `code`/`state` остаются в адресе |
| Passkey не предлагается | сертификат не доверенный (local-ca без установленного корня) или открыт не через HTTPS |
