# Running the hosted service

This service will hold a map of the weak points of every organisation that uses it. Treat
the server as a target.

> Do not take on outside organisations until an independent security review is done and a
> lawyer has reviewed the documents in `docs/legal/`.

## Before the first deployment

You need:

1. A server with Docker and Docker Compose, and ports 80 and 443 open.
2. A host name pointing at it.
3. An SMTP account for sign-in links and alerts. Set up SPF, DKIM and DMARC on the sending
   domain, or sign-in mail will land in spam.
4. Two mailboxes that someone reads: one for abuse reports, one for security reports.
5. A page describing the scanner, for `PW_CONTACT_URL`. Operators of scanned hosts will
   look for it.

## Deploying

```sh
cp deploy/env.example deploy/.env
chmod 600 deploy/.env
# fill in deploy/.env, then:
docker compose -f deploy/docker-compose.yml up -d --build
```

Generate the data key once the image is built:

```sh
docker run --rm perimeterwatch:local db new-key
```

Put it in `PW_DATA_KEYS`. **If this key is lost, stored findings cannot be read.** Keep a
copy somewhere other than the server.

Replace the placeholders in `docs/legal/security.txt` before going live. The proxy serves
it at `/.well-known/security.txt`.

Check the result:

```sh
docker compose -f deploy/docker-compose.yml ps          # all services healthy
curl -sI https://YOUR-HOST/login | grep -i strict-transport
docker compose -f deploy/docker-compose.yml exec app pwatch tools verify
```

## Where scan traffic comes from

The worker is the only part that contacts scanned hosts. In `docker-compose.yml` it has its
own network for that, and the database sits on a network with no route to the internet.

Give the worker's outbound traffic a fixed address and publish it, so that organisations
can recognise the scanner in their logs and allow or block it.

The worker must not be able to reach your own internal systems. The software refuses to
contact private and reserved addresses, but a DNS answer can change between the check and
the connection. Block outbound traffic from the worker to private ranges and to the cloud
metadata address (169.254.169.254) at the host firewall as well.

## Settings

Every setting can be given as an environment variable. `deploy/env.reference.md` lists them.
Secrets are read from the environment only. A settings file that contains anything that
looks like a secret is refused.

## Breach data: whose key

Have I Been Pwned returns a domain's results only to an account that has verified that
domain with HIBP. One key for the whole service therefore works only for domains verified
in that one HIBP account.

This is unresolved. The options are for each organisation to supply its own key, or to
agree an arrangement with Have I Been Pwned. Settle it with them in writing before
promising breach monitoring to anyone. Until then, `HIBP_API_KEY` serves only domains
verified in the account that key belongs to.

Hudson Rock is off by default and should stay off in a hosted service until you have their
written permission.

## Rotating the data key

1. Generate a new key: `pwatch db new-key`.
2. Set `PW_DATA_KEYS=NEWKEY,OLDKEY` and restart. New data is encrypted with the new key.
   Old data is still readable.
3. Keep the old key in the list for as long as any data encrypted with it exists. With the
   default retention that is 90 days.

Fingerprints for findings about people are derived from the oldest key in the list, so
they stay stable through a rotation. Removing the oldest key makes those findings appear
as new once.

## Backups

Back up the `pgdata` volume. Findings inside it are encrypted, but hostnames, scan history
and the audit log are not, so encrypt the backup too. Store the data key separately from
the backups: a backup with its key beside it protects nothing.

Test a restore before you need one.

## Retention

The worker deletes scans older than `PW_RETENTION_DAYS` (default 90), findings resolved
longer ago than that, and expired statements of authority. The latest scan of each domain
is always kept, so the next scan has something to compare with.

The audit log is not pruned. How long to keep it is a legal question listed in
`docs/legal/README.md`.

Removing a domain deletes its scans, findings and verification record at once. Audit log
entries about it remain.

## Abuse reports and opt-outs

Someone whose host received scan traffic may ask for it to stop. `docs/legal/opt-out.md`
is the draft policy. To act on a request:

1. Add the host name, address or network to `PW_NEVER_CONTACT` and restart the worker.
   From then on no scan contacts it, whatever domain it appears under.
2. Find which organisation's scan reached it, from the audit log and scan history.
3. If the host is not theirs, tell that organisation. A DNS record pointing at someone
   else's host is itself a finding worth knowing about.

```sh
PW_NEVER_CONTACT=["198.51.100.0/24","host.example.net"]
```

## Updating the scanning tools

Tool versions and checksums are pinned in `src/perimeterwatch/tools/manifest.toml`.

```sh
uv run pwatch tools bump nuclei latest    # rewrites the manifest entry
git diff src/perimeterwatch/tools/manifest.toml
```

Review the change. Compare the new checksum with the one published on the release page.
Then record fresh output from the new version for the tests, because output formats change
between releases, and rebuild the image.

After updating `nuclei-templates`, check how many templates the safety rules admit and
refuse, and look at a sample of the newly admitted ones:

```sh
uv run python -c "
from pathlib import Path
from perimeterwatch.config import load_settings
from perimeterwatch.safety.templates import select_templates
from perimeterwatch.tools.locate import ToolLocator
s = load_settings()
sel = select_templates(ToolLocator(s.resolved_tools_dir).resolve('nuclei-templates'))
print(len(sel.admitted), 'admitted', sum(sel.rejected.values()), 'refused')
"
```

## When something goes wrong

| Sign | Likely cause | What to do |
|---|---|---|
| Nobody receives sign-in mail | SMTP settings, or the sending domain lacks SPF and DKIM | Check the `app` log. Send a test alert from the Alerts page |
| Scans stay "waiting" | The worker is not running | `docker compose ps`, then the `worker` log |
| A scan "did not finish" | The worker was restarted mid-scan three times, or verification was withdrawn | The scan page gives the reason |
| "Stored data could not be decrypted" | `PW_DATA_KEYS` does not hold the key the data was written with | Restore the right key. Do not generate a new one |
| A check is always skipped | A tool or key is missing | The scan page says which, and how to add it |

Logs are JSON on standard output. Known secret values and token-shaped strings are removed
before anything is written.

## If the service itself is breached

1. Take it offline.
2. Rotate every secret in `deploy/.env`, and the data key.
3. Tell every organisation what was exposed. For each, that is at least their hostnames and
   scan history. Finding details are exposed only if the data key was taken too.
4. Organisations should treat every finding they had open as known to an attacker, and fix
   the most serious first.

Write the real procedure, with names and contact details, before onboarding anyone.
