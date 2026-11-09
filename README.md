# Guard

Лёгкий сервер авторизации для небольших веб-проектов в одном Docker-контейнере. Он даёт единый вход по Passkeys и паролю через OpenID Connect, сам выпускает TLS-сертификаты и проксирует трафик к вашим приложениям. Настраивается YAML-файлами.

```text
            ┌──────────────────────────── контейнер guard ─────────────────────────────┐
 :80/:443 ─▶│ Caddy ─┬─▶ auth.example.com ───────────────────────────▶ Rauthy :8080      │
            │        ├─▶ app1.example.com ─ forward_auth (Rauthy) ─▶ upstream app1     │
            │        └─▶ spa.example.com ───────────────────────────▶ upstream spa      │
            │                                                                           │
            │ guard-sync: /config/*.yml ─▶ Admin API Rauthy (клиенты, роли, политика)    │
            │                           └▶ Admin API Caddy (маршруты, TLS)               │
            │ s6-overlay: запуск, перезапуск и остановка процессов                       │
            └───────────────────────────────────────────────────────────────────────────┘
```

| Компонент | Роль |
|---|---|
| [Rauthy](https://github.com/sebadob/rauthy) 0.37 | OIDC-провайдер: пользователи, пароли, Passkeys, сессии, токены, встроенная БД (Hiqlite/SQLite) |
| [Caddy](https://caddyserver.com) 2.11 | Reverse proxy, HTTPS (Let's Encrypt или локальный CA), forward-auth |
| `guard-sync` (Go, этот репозиторий) | Переводит YAML в настройки Rauthy и Caddy, следит за изменениями, health, бэкапы, CLI |
| [s6-overlay](https://github.com/just-containers/s6-overlay) 3.2 | PID 1: порядок запуска, перезапуск упавших процессов, корректная остановка |

Техническое задание: [SPEC.md](SPEC.md). Что отложено: [TODO.md](TODO.md).

## Быстрый старт

### Локально (Chrome/Firefox, `*.localhost`)

```bash
cd examples/local-demo
docker compose up -d --build
docker compose logs -f guard               # дождитесь "caddy configuration applied"
docker compose exec guard cat /data/secrets/bootstrap-admin.txt
```

1. Скачайте корневой сертификат Guard: `curl -o guard-root-ca.crt http://auth.localhost/.guard/ca.crt`. Установите его в доверенные: на macOS — Связка ключей → «Всегда доверять», в Windows — «Доверенные корневые центры». Без этого браузер показывает предупреждение, а Passkeys не работают.
2. Откройте `https://auth.localhost/auth/v1/account` и войдите как `admin@example.com` с паролем из шага выше. Добавьте Passkey.
3. Откройте `https://whoami.localhost`. Guard попросит войти, после этого `whoami` покажет заголовки `X-Guard-*`.

### На сервере

```bash
git clone … guard && cd guard
cp -r config.example config
$EDITOR config/server.yml config/tls.yml config/applications/whoami.yml
docker compose up -d --build
docker compose exec guard guard-sync check     # проверка конфигурации
docker compose exec guard cat /data/secrets/bootstrap-admin.txt
```

Для Let's Encrypt укажите в `tls.yml` `mode: acme` (или оставьте `auto`) и `acme.email`. Домены должны указывать на сервер, а порты 80 и 443 должны быть открыты.

Минимальный запуск без compose:

```bash
docker build -t guard:latest .
docker run -d --name guard -p 80:80 -p 443:443 \
  -v guard-data:/data -v "$PWD/config:/config:ro" --memory=256m guard:latest
```

## Конфигурация

Вся настройка лежит в `/config`, который обычно монтируется только для чтения. Шаблоны с комментариями находятся в [config.example/](config.example/).

| Файл | Обязателен | Что задаёт |
|---|---|---|
| `server.yml` | да | домен сервера, RP ID для Passkeys, первый админ, доступ к Admin UI, SMTP, расписание бэкапов |
| `tls.yml` | нет | `auto` / `custom` / `acme` / `local-ca` |
| `security.yml` | нет | регистрация, парольная политика, сессии, Argon2, роли и группы |
| `applications/*.yml` | нет | приложения: домен, upstream, режим авторизации, OIDC-клиент |

Изменения применяются без перезапуска: `guard-sync` проверяет файлы каждые 2 секунды, можно также отправить сигнал `docker kill -s HUP guard`. Невалидная конфигурация не применяется: остаётся предыдущая рабочая, а ошибка видна в логе и в `/health`.

Секреты в YAML не хранятся. Ключ шифрования, секреты Hiqlite, API-ключ `guard-sync` и секреты OIDC-клиентов генерируются при первом запуске и лежат в `/data/secrets` с правами `0600`.

Проверить конфигурацию до запуска можно так:

```bash
docker run --rm -v "$PWD/config:/config:ro" --entrypoint guard-sync guard:latest check
docker run --rm -v "$PWD/config:/config:ro" --entrypoint guard-sync guard:latest check --caddyfile
```

## Подключение приложений

Каждый файл в `config/applications/` описывает одно приложение. Есть три режима:

| `auth.mode` | Кто проверяет вход | Когда использовать |
|---|---|---|
| `proxy` (по умолчанию) | Guard (forward-auth Rauthy) | у приложения нет своего входа; пользователь приходит в заголовках `X-Guard-*` |
| `app` | само приложение по OIDC | у приложения есть поддержка OIDC (React SPA, Express, Grafana, Gitea…) |
| `none` | никто | публичные сайты, которым нужен только TLS и прокси |

Upstream должен быть доступен Guard по имени, например в общей сети Docker. Публиковать его порты наружу не нужно. В режиме `proxy` приложение **обязано** принимать трафик только от Guard, иначе заголовки `X-Guard-*` можно подделать.

Если приложению нужно обращаться к серверу авторизации изнутри сети Docker (режим `app`, обмен кода на токен), дайте контейнеру Guard сетевой alias с доменом сервера авторизации. Тогда запросы не будут уходить наружу:

```yaml
services:
  guard:
    networks:
      apps:
        aliases: [auth.example.com]
```

Подробнее:
- [docs/integration-react.md](docs/integration-react.md): SPA на React (public client, PKCE);
- [docs/integration-express.md](docs/integration-express.md): вход в Express, проверка JWT в API, режим proxy.

Адреса, которые нужны приложениям:

| | |
|---|---|
| Issuer | `https://auth.example.com/auth/v1/` |
| Discovery | `https://auth.example.com/auth/v1/.well-known/openid-configuration` |
| Кабинет пользователя (Passkeys, пароль) | `https://auth.example.com/auth/v1/account` |
| Выход в режиме proxy | `https://<app>/.guard/logout` |

## Пользователи

- **Первый администратор** создаётся при первом запуске из `admin.bootstrap_email`. Его одноразовый пароль лежит в `/data/secrets/bootstrap-admin.txt` и в логи не попадает. Файл удаляется автоматически после первого входа. Админу обязателен Passkey (`admin.require_passkey: true`).
- **Новые пользователи без SMTP:**
  ```bash
  docker exec guard guard-sync user add anna@example.com --given-name Анна --group team --lang ru
  docker exec guard guard-sync user set-password anna@example.com
  ```
  Команда печатает одноразовый пароль. Пользователь входит в кабинет и добавляет Passkey.
- **Открытая регистрация** (`security.yml: registration.mode: open`) требует SMTP: пароль задаётся по ссылке из письма.
- Остальное (группы пользователей, блокировка, сессии) делается в Admin UI: `https://auth.example.com/auth/v1/admin`. Он открывается только с адресов из `admin.allow_from`.

## TLS

| `tls.mode` | Поведение |
|---|---|
| `custom` | сертификат и ключ из `/certs` (один на все домены: SAN или wildcard). Файлы должны читаться пользователем uid 10001. Замена файлов подхватывается без перезапуска |
| `acme` | Let's Encrypt для каждого домена (HTTP-01/TLS-ALPN-01), продление автоматическое |
| `local-ca` | собственный CA Guard. Корневой сертификат: `http://<auth-host>/.guard/ca.crt` |
| `auto` | `custom`, если есть файлы; иначе `acme`, если задан `acme.email` и все домены публичные; иначе `local-ca` |

Если ACME не смог выдать сертификат, Guard **не** переключается молча на локальный CA. Переход происходит только при `tls.acme.allow_fallback: true` по истечении `fallback_after`, и это видно в `/health`.

В браузере обычный self-signed сертификат не подходит: на сайтах с ошибкой сертификата браузеры отключают WebAuthn. С `local-ca` после установки корневого сертификата ошибок нет.

Порты `http_port` и `https_port` в `server.yml` — это публичные порты, которые видит браузер. Внутри контейнера Caddy всегда слушает 80 и 443, поэтому нестандартный порт пробрасывается так: `-p 8443:443` плюс `https_port: 8443`.

## Резервное копирование

Rauthy сам делает консистентные бэкапы БД по расписанию `backup.cron` (по умолчанию ежедневно в 02:30) и хранит их `keep_days` дней в `/data/rauthy/state_machine/backups`. Полный архив создаётся так:

```bash
docker exec -u guard guard guard-sync backup     # /data/backups/guard-<время>.tar.gz, хранятся 10 последних
docker cp guard:/data/backups/ ./guard-backups/
```

Архив содержит последний бэкап БД, `/data/secrets`, сертификаты и CA Caddy, состояние `guard-sync` и копию `/config`. **В нём есть секреты**, храните его зашифрованным. Файл живой БД никогда не копируется.

Восстановление на чистый volume:

```bash
docker volume create guard-data-new
docker run --rm -v guard-data-new:/data -v "$PWD/guard-backups:/backups:ro" \
  --entrypoint guard-sync guard:latest restore /backups/guard-20261109-023000.tar.gz
# запустите контейнер с guard-data-new: Rauthy восстановит БД при старте
```

Подробности и проверка восстановления описаны в [docs/operations.md](docs/operations.md).

## Мониторинг и логи

- `https://auth.example.com/health` отвечает `{"status":"ok|degraded|down"}`. С адресов из `admin.allow_from` отдаётся подробный отчёт: процессы, сертификаты и сроки их действия, последний бэкап, ошибки конфигурации и синхронизации.
- Docker `HEALTHCHECK` встроен: контейнер становится `unhealthy`, если Rauthy или Caddy не отвечают.
- Все логи идут в stdout контейнера с префиксами `[rauthy]`, `[caddy]`, `[sync]`, `[init]`. Пароли, ключи и токены в логи не пишутся.
- Если сервис падает, s6 перезапускает его без перезапуска контейнера. После 5 падений подряд, каждое в течение минуты после старта, контейнер останавливается, и дальше работает restart policy Docker.

## Безопасность

- Rauthy, Hiqlite и admin API Caddy слушают только loopback внутри контейнера. Снаружи открыты только 80 и 443.
- Все процессы работают от пользователя `guard` (uid 10001). Caddy получает только `cap_net_bind_service`.
- PKCE (S256) включён для всех OIDC-клиентов в режиме `app`. Redirect URI сравниваются точно, wildcard запрещены.
- Passkeys требуют проверки пользователя (`force_uv`). RP ID зафиксирован, и `guard-sync` откажется его менять без `GUARD_ALLOW_RP_ID_CHANGE=i-understand-passkeys-will-break`.
- Cookie Rauthy имеют вид `__Host-*`, `Secure`, `HttpOnly`, `SameSite=Lax/Strict`. В forward-auth есть CSRF-проверка.
- Входящие `X-Guard-*` удаляются на прокси во всех режимах.
- Admin UI закрыт для адресов вне `admin.allow_from` (по умолчанию открыт только localhost).
- Пароли хешируются Argon2id, перебор паролей ограничивается встроенной защитой Rauthy (растущие задержки и блокировка IP).

## Известные ограничения

- **Восстановление доступа не реализовано** (см. [TODO.md](TODO.md)). Без SMTP новый пароль выдаёт администратор (`guard-sync user set-password`).
- В Rauthy нет глобального отключения входа по паролю. Вместо этого можно потребовать Passkey для отдельного приложения (`auth.require_passkey`) и для админов. Пользователь может сам перевести аккаунт на вход только по Passkey.
- Rauthy не рекомендует discoverable credentials: при входе по Passkey сначала вводится e-mail (после первого входа он подставляется сам).
- Single-node: нет кластеризации. При потере диска данные восстанавливаются только из бэкапа.
- Внеплановый бэкап БД через API требует сессии администратора, поэтому `guard-sync backup` берёт последний бэкап по расписанию. Если нужна свежая копия, сделайте её в Admin UI → Config → Backups, а затем запустите `guard-sync backup`.
- Удаление роли или группы из `security.yml` ничего не удаляет в Rauthy: на них могут ссылаться пользователи.
- Клиенты, созданные вручную в Admin UI, `guard-sync` не трогает. Если `client_id` в YAML совпадает с таким клиентом, это ошибка конфигурации.
- Wildcard-сертификаты (DNS-01) не поддерживаются.

## Разработка

```bash
make test          # go vet + go test -race
make build         # bin/guard-sync
make image         # docker build
make check         # проверить ./config
```

```text
cmd/guard-sync/        CLI и точка входа
internal/config/       загрузка и валидация YAML
internal/rauthy/       config.toml Rauthy, клиент Admin API, синхронизация клиентов
internal/caddy/        генерация Caddyfile, admin API, сертификаты
internal/app/          init, демон синхронизации, пользователи
internal/backup/       архивы и восстановление
internal/health/       /health
docker/rootfs/         сервисы s6-overlay
config.example/        шаблоны конфигурации
examples/              local-demo, react, express
docs/                  интеграция, эксплуатация, тестирование
```
