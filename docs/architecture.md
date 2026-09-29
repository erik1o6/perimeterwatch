# Architecture

Perimeterwatch is one Python package with three ways in: the command line, a web service,
and a worker. All three run the same scan engine against the same database schema.

```
   pwatch scan          web service           worker
        \                   |                   /
         \            queues a scan      claims a scan
          \                 |                 /
           +----------- scan engine ---------+
                            |
        +---------+---------+---------+---------+
        |         |         |         |         |
     modules   safety    tools     report    storage
   (the checks) (the gates) (pinned binaries)   (SQLite or Postgres)
```

| Directory | What it holds |
|---|---|
| `core/` | Data model, engine, fingerprints, diffing, the table of finding kinds |
| `modules/` | One file per check |
| `safety/` | Input validation, address vetting, the subprocess runner, template rules, authorisation |
| `tools/` | The pinned tool manifest, installer and locator |
| `breach/` | Breach data sources behind one interface |
| `storage/` | Schema, encryption, the tenant-scoped repository |
| `report/` | The report view model and its HTML and JSON renderers |
| `cli/`, `web/`, `worker/` | The three ways in |

## How a scan runs

1. The domain is validated. Anything that is not plainly a public domain name is refused.
2. Authorisation is worked out afresh. If a DNS verification record is on file, it is looked
   up again now. A pass from earlier is never trusted.
3. An active scan without authorisation stops here.
4. Modules run in dependency order, up to four at once. Before each one, a preflight check
   decides whether it may run. A module that may not run is recorded as skipped, with the
   reason and how to enable it. A module that crashes or times out is recorded as failed.
   Neither stops the scan.
5. Every asset and finding gets a fingerprint.
6. Results are compared with the previous scan and stored.

## Modules

A module declares what it is and what it needs, and implements one method:

```python
@register
class EmailPosture(ScanModule):
    spec = ModuleSpec(
        name="email_posture",
        title="Email spoofing protection",
        category=Category.EMAIL,
        mode=ScanMode.PASSIVE,
        ...
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult: ...
```

The spec says how deep the module goes, which tools and keys it needs, which target
settings it needs, and which modules must run first. The engine enforces all of it, so a
module never has to check whether it is allowed to run.

To add a check: add a file in `modules/`, register it in `modules/__init__.py`, add its
finding kinds to `core/severity.py`, and run `scripts/gen_docs.py`.

## Findings and changes

A finding has an **identity** and a **state**.

- Identity is what makes it the same finding next week: its kind, what it affects, and a few
  stable keys such as a certificate's hash. The fingerprint is a hash of the identity.
- State holds the facts whose change is worth reporting, such as the list of Safe owners.
- Evidence is for display and affects neither.

Nothing volatile goes into identity or state. A certificate that expires in 29 days today
and 28 tomorrow would otherwise be reported as changed every day. Its state is a bucket
(30 days, 14 days, 7 days, expired), so it changes three times at most.

Comparing two scans gives four outcomes: new, changed, resolved, unchanged. One rule matters
more than the rest:

> A finding counts as resolved only if the module that found it ran to completion this time.

If the module was skipped, failed, or finished partially, the finding is carried as "not
re-checked". Without this rule a missing API key would make every finding look fixed.

For findings about a person, the fingerprint uses a keyed hash of the address, so
fingerprints cannot be used to confirm who is in the data.

## The safeguards and where they live

| Safeguard | Enforced in | Tested in |
|---|---|---|
| Only real public domain names are accepted | `safety/domains.py` | `tests/security/test_domain_validation.py` |
| Active scans need authorisation, with no override | `core/engine.py` | `tests/unit/test_cli.py` (TestActiveGate) |
| DNS proof is re-checked at every scan, from the domain's own nameservers | `safety/authorisation.py` | `tests/security/test_authorisation.py` |
| Only in-scope hosts with public addresses are contacted | `safety/targets.py`, `safety/netguard.py` | `tests/modules/test_tool_modules.py` |
| Answers from unexpected hosts or addresses are discarded | each tool module | `tests/modules/test_tool_modules.py` |
| Operators of hosts can opt out | `never_contact` in `safety/targets.py` | `tests/modules/test_tool_modules.py` |
| Tools are never run through a shell, and get a clean environment | `safety/subprocess.py` | `tests/security/test_tool_safety.py` |
| Tools are verified against pinned checksums | `tools/installer.py` | `tests/security/test_tool_safety.py` |
| nuclei runs only plain GET and HEAD checks | `safety/templates.py` | `tests/security/test_tool_safety.py` |
| Found credentials are never stored or tested | `modules/github_secrets.py` | `tests/modules/test_tool_modules.py` |
| Details about people need a verified domain | `modules/breaches.py` | `tests/modules/test_api_modules.py` |
| Passwords cannot be stored: no field exists for them | `breach/base.py` | `tests/modules/test_api_modules.py` |
| Findings are encrypted at rest | `storage/types.py` | `tests/unit/test_engine_and_storage.py` |
| One tenant cannot reach another's data | `storage/repo.py`, `web/deps.py` | `tests/web/test_tenancy.py` |
| Report text from scans is always escaped | `report/render_html.py` | `tests/unit/test_report.py` |

### Why nuclei gets its own rules

nuclei chooses templates by tag, and tags are not a safety boundary. The stock template that
detects web application firewalls is tagged as plain technology detection, and works by
posting a script payload. So `safety/templates.py` reads every template and admits it only
if each request is a GET or HEAD with no body, no payload and no variable substitution
beyond the target's own address, and only from the directories for exposures,
misconfiguration, takeovers, technologies, TLS and DNS. Templates tagged as CVE checks,
brute force, fuzzing or any injection class are refused whatever else they say.

Of the templates in the pinned collection, 2,093 are admitted and 654 refused. The rules are
constants in the code. No flag or setting widens them.

### Addresses can change between vetting and contact

A host is vetted by resolving it and checking every address. The tool that contacts it
resolves it again, and the answer could differ. Two things limit this. The port scanner is
given the vetted addresses, not names. The web and TLS tools report which address they
reached, and any answer from a non-public address is thrown away. Neither stops the request
being made, so a hosted worker should also run where it cannot reach internal networks:
see `docs/operations.md`.

## Storage

One schema serves both SQLite (command line, local development) and Postgres (hosted).
Migrations are in `src/perimeterwatch/migrations/` and ship inside the package.

Every table that holds customer data carries a `tenant_id`. The command line uses a single
fixed tenant. All queries go through `TenantRepo`, which is constructed with a tenant and
adds it to every query. The one exception is `storage/claims.py`, which withdraws other
tenants' verification of a domain when a new tenant proves control of it.

Finding bodies, staff address lists, verification tokens and alert channel settings are
encrypted with keys from `PW_DATA_KEYS`. Several keys can be listed: the first encrypts,
all decrypt, so keys can be rotated without downtime.

The `scans` table is also the job queue. The web service inserts a row with status
`queued`. A worker claims it, reports a heartbeat while it runs, and marks it done or
failed. A scan whose worker goes quiet for five minutes is put back, three times at most.

## The web service

Pages are rendered on the server. There is no JavaScript at all, which lets the content
security policy forbid scripts outright. The page that shows a running scan refreshes
itself with an HTTP header.

Sign-in is by emailed link. No password exists. Tokens and session cookies are stored only
as hashes. Opening a sign-in link shows a button: the link is used up when the button is
pressed, so mail scanners that fetch links do not consume it.

Lists mask names and addresses of people. Opening a finding about a person, or downloading
a report with people shown, is written to the audit log with who did it, but without the
name of the person the finding is about.

## What is deliberately absent

- No overall score or grade.
- No scraping of LinkedIn or social media, and no profiling of individuals.
- No testing of credentials found in code.
- No contact with lookalike domains.
- No way to bypass authorisation for active checks.
