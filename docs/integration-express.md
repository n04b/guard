# Подключение Express-приложения

Полный пример: [examples/express/server.js](../examples/express/server.js). В нём три сценария, используйте нужный.

## 1. Вход через OIDC (веб-приложение с сессией)

Приложение — *confidential client*: обмен кода на токен идёт на сервере, с секретом и PKCE.

Элемент в `applications` в `config/guard.yml`:

```yaml
applications:
  - name: app
    domain: app.example.com
    upstream: {host: app, port: 3000}
    auth:
      mode: app
      client_type: confidential
      redirect_uris: [https://app.example.com/callback]
      post_logout_redirect_uris: [https://app.example.com/]
```

После синхронизации секрет клиента появится в `/data/secrets/clients/app.secret`:

```bash
docker exec guard cat /data/secrets/clients/app.secret
```

Передайте его приложению через переменную окружения или Docker secret. Секрет сохраняется при перезапусках. Чтобы выпустить новый, перегенерируйте его в Admin UI и удалите файл: `guard-sync` запишет новый.

Переменные примера:

```bash
GUARD_ISSUER=https://auth.example.com/auth/v1/
OIDC_CLIENT_ID=app
OIDC_CLIENT_SECRET=...            # из app.secret
APP_URL=https://app.example.com
SESSION_SECRET=$(openssl rand -hex 32)
NODE_EXTRA_CA_CERTS=/certs/guard-root-ca.crt   # только для tls.mode: local-ca
```

Ход входа (`openid-client` v6):

```js
const oidc = await client.discovery(new URL(GUARD_ISSUER), OIDC_CLIENT_ID, OIDC_CLIENT_SECRET);

// /login
const codeVerifier = client.randomPKCECodeVerifier();
const state = client.randomState();
req.session.oidc = { codeVerifier, state };
res.redirect(client.buildAuthorizationUrl(oidc, {
  redirect_uri, scope: "openid profile email groups",
  code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
  code_challenge_method: "S256", state,
}).href);

// /callback — библиотека проверяет подпись, iss, aud, exp ID-токена
const tokens = await client.authorizationCodeGrant(oidc, currentUrl,
  { pkceCodeVerifier: codeVerifier, expectedState: state });
const claims = tokens.claims();   // sub, email, groups…
```

Выход: `client.buildEndSessionUrl(oidc, { id_token_hint, post_logout_redirect_uri })`.

> Приложение обращается к `https://auth.example.com` с сервера. В Docker дайте контейнеру Guard alias с этим доменом (см. README, раздел «Подключение приложений»), иначе запрос уйдёт через внешний адрес.

> `express-session` по умолчанию хранит сессии в памяти. В продакшене используйте хранилище (Redis, SQLite и т. п.).

## 2. API с проверкой Bearer-токена

Для API, которое принимает access token от SPA или других клиентов:

```js
import { createRemoteJWKSet, jwtVerify } from "jose";

const meta = oidc.serverMetadata();                 // или fetch discovery
const jwks = createRemoteJWKSet(new URL(meta.jwks_uri));

const { payload } = await jwtVerify(token, jwks, {
  issuer: meta.issuer,          // "https://auth.example.com/auth/v1/"
  audience: "spa",              // client_id, для которого выпущен токен
  algorithms: ["RS256", "RS384", "RS512", "EdDSA"],
});
```

Обязательные проверки по ТЗ: подпись (JWKS), `iss`, `aud`, `exp`. `jose` проверяет `exp` и `nbf` автоматически. Группы и роли передаются в claims `groups` и `roles`, если запрошен scope `groups`.

Не используйте issuer без завершающего слэша: Rauthy выпускает токены с `iss` = `https://auth.example.com/auth/v1/`. Безопаснее всего брать его из discovery, как в примере.

## 3. Режим proxy: пользователь из заголовков

Если у приложения нет своего входа, включите `auth.mode: proxy`. Guard проверит сессию сам и передаст пользователя в заголовках:

| Заголовок | Значение |
|---|---|
| `X-Guard-User` | id пользователя (стабильный, используйте как ключ) |
| `X-Guard-Email`, `X-Guard-Email-Verified` | e-mail и признак подтверждения |
| `X-Guard-Username` | preferred username, если задан |
| `X-Guard-Given-Name`, `X-Guard-Family-Name` | имя и фамилия |
| `X-Guard-Groups`, `X-Guard-Roles` | списки через запятую |
| `X-Guard-Mfa` | `true`, если у пользователя есть Passkey |

Значения с не-ASCII символами percent-encoded в UTF-8: декодируйте их через `decodeURIComponent`.

Условия безопасности:
- Приложение доступно **только** через Guard: не публикуйте его порты и держите его в отдельной сети Docker.
- Guard удаляет входящие `X-Guard-*` от клиента, поэтому доверять им можно только при выполнении первого условия.
- Пути `/.guard/callback` и `/.guard/logout` перехватываются Guard и до приложения не доходят.
- Для выхода поставьте ссылку на `/.guard/logout`: она завершает сессию Guard, и после этого все proxy-приложения снова потребуют вход.
