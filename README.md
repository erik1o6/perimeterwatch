# Perimeterwatch

Perimeterwatch shows an organisation what an outsider can find out about its systems, and
tells it when that changes. It is built for crypto and web3 teams, and it only ever looks at
an organisation's own domain, with that organisation's consent.

You name your domain. It finds your hostnames, checks whether your email can be spoofed,
looks for lookalike domains, dangling DNS records, credentials left in public code, changes
to your multisig signers, and staff addresses in breach data. Each scan is compared with the
last, so you see what is new.

> **Status: beta.** The command-line tool works, and the hosted service runs at
> [perimeterwatch.org](https://perimeterwatch.org). Both are covered by automated tests.
> Neither has had an independent security review, and the
> [legal documents](https://perimeterwatch.org/legal) are drafts that no lawyer has reviewed.
> Rely on it accordingly.

## What it checks

| Area | What you learn | Depth |
|---|---|---|
| Hostnames | Every name under your domain seen in public records | passive |
| DNS | DNSSEC, CAA, wildcards, names pointing at private addresses | passive |
| DNSSEC quality | Weak algorithms, signatures about to expire, zones that can be listed in full | passive |
| Email | Whether SPF, DMARC, DKIM and MTA-STS stop others sending as you | passive |
| Lookalike domains | Registered names resembling yours, and whether they can take mail | passive |
| Dangling DNS | Names pointing at hosted resources that no longer exist | passive |
| Public code | Credentials committed to your public GitHub repositories | passive |
| Multisig | Owners and threshold of your Safe, and any change to them | passive |
| Multisig modules | Modules, guard and fallback handler of your Safe. A module can move funds without an owner's signature | passive |
| Job postings | Which systems your own postings name | passive |
| Domain registration | Expiry, transfer lock, registry lock, and changes of registrar or nameservers | passive |
| SPF chain | Domains your SPF record trusts that no longer exist | passive |
| Phishing lists | Lookalike domains already reported as phishing, and your own domain if a blocklist names it | passive |
| Web archives | Sensitive-looking addresses that archives have recorded | passive |
| Packages | Lookalikes of your npm and PyPI packages, changes to who can publish, and releases that lost their provenance | passive |
| Repository health | Weak branch protection and risky workflow settings | passive |
| Contracts | Owner, admin and implementation of your contracts, and any change | passive |
| ENS names | Expiry, and changes of owner or target address | passive |
| Frontend pointers | Changes to the content your ENS name or DNSLink record points to | passive |
| Origin servers | Servers behind your content delivery network that can be reached directly | passive |
| Outside services | The services your domain depends on, and any change to the list | passive |
| Breach data | Staff addresses in breaches and malware logs | passive, verified domain |
| Frontend | Changes to the scripts your site serves; missing security headers | probe |
| Web servers | What answers, and what software it reveals | probe |
| Certificates | Expired, expiring or mismatched certificates | probe |
| Security contact | A missing, expired or invalid `security.txt` | probe |
| Nameservers | Servers that do not answer for your zone, disagree, or answer for anyone | probe |
| Ports | Services reachable from the internet, over IPv4 and IPv6 | active |
| Exposures | Readable config files, open admin pages | active |
| TLS configuration | Old TLS versions and weak cipher suites still accepted | active |
| Zone transfer | Nameservers that hand out your whole DNS zone | active |
| SSH servers | Weak algorithms offered, and changes of host key | active |
| Storage buckets | Buckets your DNS points at that anyone can list or write to | active |

The three depths:

- **Passive** consults public records and third-party indexes. It makes no connection to
  your hosts. Your DNS records are read through public resolvers, as any visitor's would be.
- **Probe** adds one ordinary web request and one TLS handshake per host.
- **Active** adds a scan of common ports and read-only checks for known exposures.

## Consent comes first

- Active checks need proof that you control the domain: a DNS record, checked again before
  every active scan. Remove the record and authorisation is gone. There is no override.
- Details about individual people are shown only for a domain verified that way.
- Hosts outside your domain are never contacted. Neither are hosts that resolve to private
  addresses, nor lookalike domains.
- Passwords are never collected. Credentials found in code are never stored or tested.
- Reports give no score or grade.

`docs/architecture.md` explains how each of these is enforced and tested.

## Quick start

You need [uv](https://docs.astral.sh/uv/) and Python 3.13 or newer.

```sh
uv sync
uv run pwatch init
uv run pwatch doctor            # shows what is ready and what is missing
uv run pwatch tools install --all   # optional: downloads and verifies the scanning tools
uv run pwatch scan yourproject.xyz
```

The scan prints a summary and writes `report.html` and `report.json` under `pw-reports/`.
Run it again later to see what changed.

Tools and keys are optional. A check that lacks one is skipped, and the report says so and
says how to enable it.

### Going deeper

```sh
# Tell it where else to look
uv run pwatch target add yourproject.xyz --github-org yourorg \
    --safe eth:0xYourSafeAddress --greenhouse yourboard \
    --npm @yourorg/sdk --contract eth:0xYourContract=Vault --ens yourproject.eth

# Prove you control the domain, then run active checks
uv run pwatch verify init yourproject.xyz     # prints a DNS record to create
uv run pwatch verify check yourproject.xyz
uv run pwatch scan yourproject.xyz --active
```

Keys go in the environment or in a `.env` file, never in a settings file. Copy
`.env.example` to start. `pwatch doctor` lists each key and what it enables.

### The web service

```sh
uv run pwatch serve      # http://127.0.0.1:8000
uv run pwatch worker     # in a second terminal
```

In development, sign-in links are printed in the `serve` terminal instead of being emailed.
To host it, see `docs/operations.md` and `deploy/`.

## Commands

| Command | Purpose |
|---|---|
| `pwatch scan DOMAIN` | Scan and write a report. Add `--probe` or `--active` to go deeper |
| `pwatch report DOMAIN` | Write a stored scan's report again. `--redact-personal` masks people |
| `pwatch diff DOMAIN` | Show what changed between two scans |
| `pwatch target add\|list\|show\|remove` | Manage domains and their details |
| `pwatch verify init\|check DOMAIN` | Prove control of a domain by DNS record |
| `pwatch authorise DOMAIN` | Record a statement of authority, where a DNS record is not possible |
| `pwatch tools list\|install\|verify` | Manage the pinned scanning tools |
| `pwatch modules list` | List every check and what it needs |
| `pwatch doctor` | Check the setup. Never prints a secret |
| `pwatch db migrate\|purge\|new-key` | Database upkeep |
| `pwatch serve`, `pwatch worker` | Run the web service |

Exit codes: 0 success, 1 error, 2 invalid input, 3 a check was skipped (with `--strict`),
4 authorisation refused.

## Development

```sh
make check      # lint, types, tests
```

No test touches the network. Tool output is replayed from recordings in `tests/fixtures/`.
Tests marked `live` do use the network. They are excluded by default and may only target
domains you own: see `tests/integration/README.md`.

## Documents

- `docs/architecture.md`: how it is built, and how the safeguards are enforced
- `docs/modules.md`: every check, what it contacts, and every finding it can raise
- `docs/operations.md`: hosting, keys, backups, abuse reports, updating tools
- `docs/hosting-perimeterwatch-org.md`: the plan for hosting the service at perimeterwatch.org
- `docs/sample-report/`: a real report, from a scan of the project's own domain
- `docs/report.schema.json`: the format of `report.json`
- `docs/grant/`: funding proposal drafts
- `src/perimeterwatch/legal/`: terms, privacy and policy drafts, not yet reviewed by a lawyer. The hosted
  service serves them at `/legal`. `docs/legal/README.md` lists what is still open

## Licence

Apache-2.0. See `LICENSE`. The scanning tools are separate programs under their own
licences, listed in `THIRD_PARTY_NOTICES.md`.

To report a vulnerability, see `SECURITY.md`.
