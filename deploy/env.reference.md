# Settings reference

Every setting is an environment variable. Update this file when a setting is added.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `PW_ENV` | dev | `dev` or `production`. Outside `dev`, HTTPS, SMTP and an abuse address are required, and cookies are marked Secure. |
| `PW_DATA_DIR` | per-user data directory | Where the local database, data key and tools live. |
| `PW_DATABASE_URL` | empty | SQLAlchemy address of the database. Empty means a SQLite file in the data directory. |
| `PW_TOOLS_DIR` | empty | Where the scanning tools are installed. Empty means inside the data directory. |
| `PW_ALLOW_PATH_TOOLS` | false | Also look for tools on PATH. Leave off: unrelated programs share these names. |
| `PW_CONTACT_URL` | https://perimeterwatch.org | A page about the scanner. Sent with every request. |
| `PW_ABUSE_EMAIL` | empty | Where operators of scanned hosts can complain. Sent with every request. |
| `PW_RETENTION_DAYS` | 90 | Days to keep stored scans and resolved findings. |
| `PW_CONCURRENCY` | 4 | How many checks run at once within a scan. |
| `PW_DNS_TIMEOUT_S` | 4.0 | Seconds to wait for a DNS answer. |
| `PW_HTTP_TIMEOUT_S` | 20.0 | Seconds to wait for an API answer. |
| `PW_PER_HOST_RPS` | 2.0 | Requests per second to any one service. |
| `PW_LOOKALIKE_MAX_PERMUTATIONS` | 6000 | How many name variations to look up. |
| `PW_DKIM_SELECTORS_EXTRA` | empty | Extra DKIM selector names to try, as a JSON list. |
| `PW_NEVER_CONTACT` | empty | Hosts, addresses or networks that must never be contacted, as a JSON list. |
| `PW_BREACH_PROVIDERS` | ['hibp'] | Breach sources to use, as a JSON list. |
| `PW_HUDSONROCK_ENABLED` | false | Use Hudson Rock's count-only lookup. Needs their written permission in a hosted service. |
| `PW_BASE_URL` | http://127.0.0.1:8000 | Public address of the web service. Used in sign-in links and alerts. |
| `PW_SIGNUP_OPEN` | true | Whether new email addresses may create an account. |
| `PW_SCAN_REQUIRES_VERIFICATION` | true | Scan a domain only once control of it is proved. Leave on in a hosted service. |
| `PW_MAX_TARGETS_PER_TENANT` | 10 | Domains one organisation may add. |
| `PW_MIN_SCAN_INTERVAL_MINUTES` | 360 | Shortest gap between two requested scans of a domain. |
| `PW_DEFAULT_SCAN_INTERVAL_HOURS` | 24 | How often a newly added domain is scanned automatically. |
| `PW_WORKER_POLL_SECONDS` | 5.0 | How often an idle worker looks for work. |
| `PW_SMTP_HOST` | empty | SMTP server for sign-in links and email alerts. |
| `PW_SMTP_PORT` | 587 | SMTP port. STARTTLS is always used. |
| `PW_SMTP_USER` | empty | SMTP user name. The password is `PW_SMTP_PASSWORD`. |
| `PW_MAIL_FROM` | Perimeterwatch <no-reply@localhost> | Sender shown on outgoing mail. |
| `PW_TRUST_PROXY_HEADERS` | false | Take the visitor's address from the proxy. Turn on only behind the bundled proxy. |
| `PW_CERTSTREAM_URL` | empty | Websocket address of a self-hosted certstream server. When set, the worker watches newly issued certificates for names imitating verified domains. |
| `PW_NEVER_CONTACT` | empty | Hosts, addresses or networks that must never be contacted, as a JSON list. |

## Secrets

Read from the environment or `.env` only. A settings file holding any of these is refused.

| Variable | Meaning |
|---|---|
| `GITHUB_TOKEN` | Read-only GitHub token. Secret scanning needs it. |
| `HIBP_API_KEY` | Have I Been Pwned key. See `docs/operations.md` on whose key this should be. |
| `VIRUSTOTAL_API_KEY` | More subdomain sources. |
| `SECURITYTRAILS_API_KEY` | More subdomain sources. |
| `CERTSPOTTER_API_KEY` | More subdomain sources. |
| `CHAOS_API_KEY` | More subdomain sources. |
| `PW_RPC_ETH_MAINNET` | Ethereum RPC address. Safe multisig checks need it. |
| `PW_DATA_KEYS` | Encryption keys for stored data, newest first, comma separated. Required outside `dev`. |
| `PW_SMTP_PASSWORD` | SMTP password. |

## Used only by Docker Compose

| Variable | Meaning |
|---|---|
| `SITE_ADDRESS` | Public host name. The proxy obtains a certificate for it. |
| `ACME_EMAIL` | Contact address given to the certificate authority. |
| `POSTGRES_PASSWORD` | Database password. Compose builds `PW_DATABASE_URL` from it. |
