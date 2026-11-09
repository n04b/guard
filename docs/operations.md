# Эксплуатация

## Структура данных

```text
/data
├── rauthy/                 БД Rauthy (Hiqlite)
│   └── state_machine/backups/   автоматические бэкапы БД
├── caddy/                  сертификаты, ACME-аккаунт, локальный CA (pki/authorities/local)
├── secrets/                0700; ключ шифрования, секреты Hiqlite, API-ключ, секреты клиентов
├── guard/
│   ├── state.json          что создал guard-sync (клиенты, RP ID, ACME-fallback)
│   ├── Caddyfile           последний принятый Caddy конфиг
│   └── rauthy/config.toml  сгенерированный конфиг Rauthy (0600)
└── backups/                архивы guard-sync backup
```

**Ключ шифрования** (`secrets/rauthy-enc-key`) нужен для расшифровки секретов в БД. Если его потерять, бэкап БД станет бесполезен. Поэтому он входит в архив.

## Первый запуск

1. `guard-init` (root) проверяет `/config`, выставляет владельца `/data` и запускает `guard-sync init` от пользователя `guard`.
2. `guard-sync init` генерирует секреты, `config.toml` Rauthy, bootstrap API-ключ и пароль администратора, затем начальный Caddyfile.
3. Стартуют Rauthy и Caddy, затем `guard-sync run`. Демон создаёт OIDC-клиентов, роли, группы и парольную политику, удаляет bootstrap-файлы и загружает Caddyfile.

Если конфигурация невалидна при **первом** запуске, контейнер останавливается с понятной ошибкой. При последующих запусках он стартует с последней рабочей конфигурацией.

## Изменение конфигурации

Отредактируйте `config/guard.yml`. Через 2 секунды в логе появится `configuration files changed, applying`. Проверить результат:

```bash
docker exec guard guard-sync check
docker logs --since 1m guard | grep '\[sync\]'
curl -s https://auth.example.com/health        # с адреса из admin.allow_from — подробно
```

Удаление приложения из списка `applications` сразу убирает маршрут, а OIDC-клиент отключается (`on_remove: disable`) или удаляется (`on_remove: delete`). Если вернуть приложение в список, клиент снова включится.

**Смена домена сервера авторизации или `webauthn.rp_id`** делает все Passkeys недействительными. `guard-sync` откажется применять такое изменение, пока контейнер не запущен с `GUARD_ALLOW_RP_ID_CHANGE=i-understand-passkeys-will-break`.

## Резервное копирование

Автоматически: Rauthy делает бэкап БД по `backup.cron` и хранит его `keep_days` дней.

Полный архив:

```bash
docker exec -u guard guard guard-sync backup          # хранит 10 последних (--keep N)
docker exec -u guard guard guard-sync backup --output /data/backups/manual.tar.gz
```

Скопируйте архивы с сервера, например по cron на хосте:

```bash
0 4 * * * docker exec -u guard guard guard-sync backup && docker cp guard:/data/backups/. /srv/backup/guard/
```

Для внепланового снимка БД (перед обновлением) нажмите в Admin UI → Config → Backups «Create Backup», затем выполните `guard-sync backup`.

## Восстановление

1. Остановите старый контейнер. Создайте новый volume или используйте `--force`, чтобы заменить БД в текущем.
2. Распакуйте архив:
   ```bash
   docker run --rm -v guard-data:/data -v /srv/backup/guard:/backups:ro \
     --entrypoint guard-sync guard:latest restore /backups/guard-20261109-040000.tar.gz [--force]
   ```
   Секреты, сертификаты и состояние кладутся на место, файл БД — в `/data/guard/restore/`, а копия конфигурации — в `/data/restored-config/`.
3. Запустите контейнер. Rauthy восстановит БД при старте (`HQL_BACKUP_RESTORE`), а `guard-sync` уберёт временные файлы, как только Rauthy ответит.
4. Проверьте: вход по Passkey и паролю, `/health`, список клиентов в Admin UI.

Восстановление стоит регулярно проверять на отдельном volume:

```bash
docker volume create guard-restore-test
docker run --rm -v guard-restore-test:/data -v /srv/backup/guard:/backups:ro \
  --entrypoint guard-sync guard:latest restore /backups/<архив>
docker run --rm -p 8443:443 -v guard-restore-test:/data -v "$PWD/config:/config:ro" guard:latest
```

## Обновление

```bash
git pull && docker compose build && docker compose up -d
```

Перед обновлением Rauthy (`RAUTHY_VERSION` в Dockerfile) сделайте архив и прочитайте его release notes: миграции БД выполняются автоматически при старте.

## Диагностика

| Симптом | Где смотреть |
|---|---|
| Контейнер сразу останавливается | `docker logs guard`: ошибки `[init]` / `[sync]` про конфигурацию или права на файлы |
| `/health` = degraded | `curl https://auth…/health` с адреса из `allow_from`: поля `problems`, `config_error`, `sync_error` |
| Нет сертификата Let's Encrypt | DNS домена, открыт ли порт 80/443, лог `[caddy]` с `tls.obtain` |
| `client ... was not created by Guard` | в Rauthy уже есть клиент с этим `client_id`: удалите его в Admin UI или смените `client_id` |
| Бесконечный редирект в режиме proxy | cookie не ставятся: проверьте, что сайт открыт по HTTPS, а сертификат доверенный |
| Admin UI отвечает 403 | ваш адрес не входит в `admin.allow_from` (за Docker NAT это может быть адрес шлюза) |
| `no Rauthy API key` | `/data/secrets/rauthy-api-key` потерян: создайте ключ в Admin UI → API Keys с правами Clients (все), Groups/Roles (read, create), Secrets (read, update), Users (read, create, update) и сохраните `имя$секрет` в этот файл |

Подробный лог `guard-sync`: переменная `GUARD_DEBUG=1`.

## Память

Ориентиры, которые нужно подтвердить замером на вашей нагрузке (`docker stats guard`, `ps -o rss`):
- Rauthy на SQLite в простое занимает десятки МБ. Пик при входах ≈ `hashing.memory_mib × hashing.max_parallel_hashes` (по умолчанию 64 МБ).
- Caddy занимает десятки МБ, `guard-sync` — около 10 МБ.

Лимит `--memory=256m` оставляет запас. Если вход становится медленным под нагрузкой, увеличьте `max_parallel_hashes` и лимит памяти вместе.
