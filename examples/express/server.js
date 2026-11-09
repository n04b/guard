// Express + Guard: три способа интеграции в одном файле.
//
//   1. Веб-приложение с входом через OIDC (auth.mode: app, confidential).
//   2. API, которое проверяет Bearer-токены (например, от SPA).
//   3. Приложение за Guard в режиме proxy: читает заголовки X-Guard-*.
//
// Переменные окружения:
//   GUARD_ISSUER         https://auth.example.com/auth/v1/
//   OIDC_CLIENT_ID       client_id приложения из guard.yml (по умолчанию = name)
//   OIDC_CLIENT_SECRET   содержимое /data/secrets/clients/<name>.secret
//   APP_URL              https://app.example.com (публичный адрес приложения)
//   API_AUDIENCE         client_id, чьи access token принимает API (по умолчанию OIDC_CLIENT_ID)
//   SESSION_SECRET       случайная строка для подписи cookie сессии
//   NODE_EXTRA_CA_CERTS  путь к корневому CA Guard, если tls.mode: local-ca
import express from "express";
import session from "express-session";
import * as client from "openid-client";
import { createRemoteJWKSet, jwtVerify } from "jose";

const {
  GUARD_ISSUER,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  APP_URL,
  SESSION_SECRET,
  PORT = "3000",
} = process.env;
const API_AUDIENCE = process.env.API_AUDIENCE || OIDC_CLIENT_ID;

for (const [k, v] of Object.entries({ GUARD_ISSUER, OIDC_CLIENT_ID, APP_URL, SESSION_SECRET })) {
  if (!v) throw new Error(`${k} is required`);
}

// Discovery: issuer, endpoints и jwks_uri берутся из
// <issuer>.well-known/openid-configuration — ничего не захардкожено.
const oidc = await client.discovery(new URL(GUARD_ISSUER), OIDC_CLIENT_ID, OIDC_CLIENT_SECRET);
const meta = oidc.serverMetadata();
const jwks = createRemoteJWKSet(new URL(meta.jwks_uri));

const app = express();
app.set("trust proxy", 1); // перед приложением стоит Guard (Caddy)
app.use(
  session({
    name: "app.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 8 * 3600 * 1000 },
  }),
);

// ---------- 1. Вход через OIDC (Authorization Code + PKCE) ----------

const redirectUri = new URL("/callback", APP_URL).href;

app.get("/login", async (req, res) => {
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  req.session.oidc = { codeVerifier, state, returnTo: req.query.returnTo || "/" };
  const url = client.buildAuthorizationUrl(oidc, {
    redirect_uri: redirectUri,
    scope: "openid profile email groups",
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
  });
  res.redirect(url.href);
});

app.get("/callback", async (req, res, next) => {
  try {
    const pending = req.session.oidc;
    if (!pending) return res.redirect("/login");
    const tokens = await client.authorizationCodeGrant(
      oidc,
      new URL(req.originalUrl, APP_URL),
      { pkceCodeVerifier: pending.codeVerifier, expectedState: pending.state },
    );
    // ID token уже проверен библиотекой: подпись, iss, aud, exp, nonce.
    const claims = tokens.claims();
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { sub: claims.sub, email: claims.email, name: claims.name, groups: claims.groups ?? [] };
      req.session.idToken = tokens.id_token;
      res.redirect(pending.returnTo);
    });
  } catch (err) {
    next(err);
  }
});

app.get("/logout", (req, res) => {
  const idToken = req.session.idToken;
  req.session.destroy(() => {
    // RP-initiated logout: Rauthy завершает сессию и возвращает на сайт.
    // post_logout_redirect_uri должен быть в post_logout_redirect_uris.
    const url = client.buildEndSessionUrl(oidc, {
      ...(idToken ? { id_token_hint: idToken } : {}),
      post_logout_redirect_uri: new URL("/", APP_URL).href,
    });
    res.redirect(url.href);
  });
});

function requireLogin(req, res, next) {
  if (req.session.user) return next();
  res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
}

app.get("/", (req, res) => {
  res.type("text").send(req.session.user ? `Привет, ${req.session.user.email}` : "Не выполнен вход: /login");
});

app.get("/profile", requireLogin, (req, res) => res.json(req.session.user));

// ---------- 2. API с проверкой Bearer-токена ----------

async function requireBearer(req, res, next) {
  const [scheme, token] = (req.get("authorization") || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "missing bearer token" });
  try {
    // Подпись (JWKS), iss, aud, exp и nbf проверяет jose.
    const { payload } = await jwtVerify(token, jwks, {
      issuer: meta.issuer,
      audience: API_AUDIENCE,
      algorithms: ["RS256", "RS384", "RS512", "EdDSA"],
      clockTolerance: 5,
    });
    req.auth = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: "invalid token", detail: err.code || err.message });
  }
}

function requireGroup(group) {
  return (req, res, next) =>
    (req.auth?.groups ?? []).includes(group) ? next() : res.status(403).json({ error: `group ${group} required` });
}

app.get("/api/me", requireBearer, (req, res) => res.json({ sub: req.auth.sub, groups: req.auth.groups ?? [] }));
app.get("/api/team", requireBearer, requireGroup("team"), (req, res) => res.json({ ok: true }));

// ---------- 3. Режим proxy: пользователь из заголовков Guard ----------
//
// Используйте ТОЛЬКО если приложение доступно исключительно через Guard
// (нет опубликованных портов, отдельная сеть Docker). Guard удаляет
// входящие X-Guard-* и выставляет их сам; значения percent-encoded в UTF-8.

function guardUser(req) {
  const h = (name) => {
    const v = req.get(name);
    return v === undefined ? undefined : decodeURIComponent(v);
  };
  const id = h("x-guard-user");
  if (!id) return null;
  return {
    id,
    email: h("x-guard-email"),
    username: h("x-guard-username"),
    givenName: h("x-guard-given-name"),
    familyName: h("x-guard-family-name"),
    groups: (h("x-guard-groups") || "").split(",").filter(Boolean),
    roles: (h("x-guard-roles") || "").split(",").filter(Boolean),
    passkey: h("x-guard-mfa") === "true",
  };
}

app.get("/proxied/whoami", (req, res) => {
  const user = guardUser(req);
  if (!user) return res.status(401).send("not behind Guard proxy mode");
  res.json(user);
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).send("authentication error");
});

app.listen(Number(PORT), () => console.log(`listening on :${PORT}`));
