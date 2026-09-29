# Settings reference

Every setting is an environment variable. Update this file when a setting is added.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `PARAPET_ENV` | dev | `dev` or `production`. Outside `dev`, HTTPS, SMTP and an abuse address are required, and cookies are marked Secure. |
| `PARAPET_DATA_DIR` | per-user data directory | Where the local database, data key and tools live. |
| `PARAPET_DATABASE_URL` | empty | SQLAlchemy address of the database. Empty means a SQLite file in the data directory. |
| `PARAPET_TOOLS_DIR` | empty | Where the scanning tools are installed. Empty means inside the data directory. |
| `PARAPET_ALLOW_PATH_TOOLS` | false | Also look for tools on PATH. Leave off: unrelated programs share these names. |
| `PARAPET_CONTACT_URL` | https://github.com/erik1o6/parapet | A page about the scanner. Sent with every request. |
| `PARAPET_ABUSE_EMAIL` | empty | Where operators of scanned hosts can complain. Sent with every request. |
| `PARAPET_RETENTION_DAYS` | 90 | Days to keep stored scans and resolved findings. |
| `PARAPET_CONCURRENCY` | 4 | How many checks run at once within a scan. |
| `PARAPET_DNS_TIMEOUT_S` | 4.0 | Seconds to wait for a DNS answer. |
| `PARAPET_HTTP_TIMEOUT_S` | 20.0 | Seconds to wait for an API answer. |
| `PARAPET_PER_HOST_RPS` | 2.0 | Requests per second to any one service. |
| `PARAPET_LOOKALIKE_MAX_PERMUTATIONS` | 6000 | How many name variations to look up. |
| `PARAPET_DKIM_SELECTORS_EXTRA` | empty | Extra DKIM selector names to try, as a JSON list. |
| `PARAPET_NEVER_CONTACT` | empty | Hosts, addresses or networks that must never be contacted, as a JSON list. |
| `PARAPET_BREACH_PROVIDERS` | ['hibp'] | Breach sources to use, as a JSON list. |
| `PARAPET_HUDSONROCK_ENABLED` | false | Use Hudson Rock's count-only lookup. Needs their written permission in a hosted service. |
| `PARAPET_BASE_URL` | http://127.0.0.1:8000 | Public address of the web service. Used in sign-in links and alerts. |
| `PARAPET_SIGNUP_OPEN` | true | Whether new email addresses may create an account. |
| `PARAPET_SCAN_REQUIRES_VERIFICATION` | true | Scan a domain only once control of it is proved. Leave on in a hosted service. |
| `PARAPET_MAX_TARGETS_PER_TENANT` | 10 | Domains one organisation may add. |
| `PARAPET_MIN_SCAN_INTERVAL_MINUTES` | 360 | Shortest gap between two requested scans of a domain. |
| `PARAPET_DEFAULT_SCAN_INTERVAL_HOURS` | 24 | How often a newly added domain is scanned automatically. |
| `PARAPET_WORKER_POLL_SECONDS` | 5.0 | How often an idle worker looks for work. |
| `PARAPET_SMTP_HOST` | empty | SMTP server for sign-in links and email alerts. |
| `PARAPET_SMTP_PORT` | 587 | SMTP port. STARTTLS is always used. |
| `PARAPET_SMTP_USER` | empty | SMTP user name. The password is `PARAPET_SMTP_PASSWORD`. |
| `PARAPET_MAIL_FROM` | Parapet <no-reply@localhost> | Sender shown on outgoing mail. |
| `PARAPET_TRUST_PROXY_HEADERS` | false | Take the visitor's address from the proxy. Turn on only behind the bundled proxy. |

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
| `PARAPET_RPC_ETH_MAINNET` | Ethereum RPC address. Safe multisig checks need it. |
| `PARAPET_DATA_KEYS` | Encryption keys for stored data, newest first, comma separated. Required outside `dev`. |
| `PARAPET_SMTP_PASSWORD` | SMTP password. |

## Used only by Docker Compose

| Variable | Meaning |
|---|---|
| `SITE_ADDRESS` | Public host name. The proxy obtains a certificate for it. |
| `ACME_EMAIL` | Contact address given to the certificate authority. |
| `POSTGRES_PASSWORD` | Database password. Compose builds `PARAPET_DATABASE_URL` from it. |
