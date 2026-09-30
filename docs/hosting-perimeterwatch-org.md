# Hosting the service at perimeterwatch.org

The steps to take `perimeterwatch.org` from a fresh registration to a running service. The
general guide is `operations.md`. This file is the plan for this one domain.

The domain is registered with Cloudflare, which also runs its DNS. Every DNS step below is
done in the Cloudflare dashboard under the domain's **DNS** section.

> Do not onboard outside organisations until the independent security review is done and a
> lawyer has reviewed the legal drafts in `src/perimeterwatch/legal/`. Until then the service is a beta:
> say so to anyone who joins.

## What costs money

The project takes on no paid subscription before it is funded. Most of this plan is free.
One part is not.

| Part | Cost |
|---|---|
| DNS, DNSSEC, inbound mail forwarding | Free with Cloudflare |
| TLS certificates | Free, obtained automatically by the bundled proxy |
| Sending sign-in links and alerts | Free with Resend, up to 3,000 messages a month |
| **A server** | **Not free.** About €5.49 a month at Hetzner for 2 vCPUs and 4 GB of memory, plus a small charge for the IPv4 address, before VAT |
| Breach data | Paid. Left switched off until funded |

Until there is a server, steps 1 to 3 can still be done. They fix every finding in the
sample report and cost nothing.

## Step 1: fix what the sample report found

Do these first. They are free, and they turn the sample report's findings into "Resolved"
on the next scan.

| Finding | What to do in Cloudflare |
|---|---|
| Not signed with DNSSEC | **DNS > Settings > DNSSEC > Enable**. Cloudflare is also the registrar, so it publishes the DS record itself |
| No CAA record | Add the CAA records below |
| No SPF record | Added by step 2 |
| No DMARC record | Added by step 2 |

CAA records, so that only the certificate authorities the proxy uses may issue for the domain:

| Type | Name | Tag | Value |
|---|---|---|---|
| CAA | `@` | issue | `letsencrypt.org` |
| CAA | `@` | issue | `pki.goog` |
| CAA | `@` | issuewild | `;` |

Caddy, the bundled proxy, uses Let's Encrypt and falls back to another authority if it is
unavailable. If a certificate ever fails to issue, check Caddy's log for the authority it
tried and add that authority here. Cloudflare may also add authorities of its own if you
turn its proxy on for a record.

## Step 2: mail

Two mailboxes are needed before the service contacts anyone's hosts:

- `abuse@perimeterwatch.org`, sent with every scan request, for operators of scanned hosts.
- `security@perimeterwatch.org`, for reports of vulnerabilities in the service.

**Receiving.** Turn on **Email > Email Routing** in Cloudflare and forward both addresses
to a mailbox you read. Cloudflare adds the MX records and an SPF record itself. The
forwarding address is not visible to people who write to you, but your replies come from
your own mailbox unless you set up sending as well.

**Sending.** Sign-in links and alerts go out through Resend. Its free plan allows 3,000
messages a month and 100 a day, which is far more than sign-in links and alerts need.
Figures and settings below were read from Resend's own pages on 30 September 2026.

1. Create a Resend account and add `perimeterwatch.org` as a domain.
2. Resend shows three DNS records. Add them in Cloudflare, each set to **DNS only**.
   Copy the values from Resend. When pasting a name, leave the domain off: enter `send`,
   not `send.perimeterwatch.org`.

   | Type | Name | Purpose |
   |---|---|---|
   | MX | `send` | Where bounces are returned |
   | TXT | `send` | SPF for the sending subdomain |
   | TXT | `resend._domainkey` | DKIM key |

   These sit on the `send` subdomain, so they do not clash with the SPF record that
   Cloudflare's email routing puts on the domain itself.
3. Create an API key in Resend with permission to send only. It is the SMTP password.
4. Put these in `deploy/.env` on the server:

   ```sh
   PW_SMTP_HOST=smtp.resend.com
   PW_SMTP_PORT=587
   PW_SMTP_USER=resend
   PW_SMTP_PASSWORD=<the API key>
   PW_MAIL_FROM=Perimeterwatch <no-reply@perimeterwatch.org>
   ```

   Port 587 is the one to use. Hetzner blocks outbound ports 25 and 465 on cloud servers
   and leaves 587 open.
5. Add a DMARC record:

   | Type | Name | Value |
   |---|---|---|
   | TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@perimeterwatch.org` |

   Forward `dmarc@` too, or use Cloudflare's DMARC Management, which gives you an address
   for reports. After a week or two of clean reports, change `p=quarantine` to `p=reject`.

## Step 3: prove control to Perimeterwatch itself

The service should monitor its own domain. From the command line:

```sh
uv run pwatch verify init perimeterwatch.org
```

Add the TXT record it prints, then:

```sh
uv run pwatch verify check perimeterwatch.org
uv run pwatch scan perimeterwatch.org --active
```

## Step 4: the server

The server exists: a Hetzner CX23 in Falkenstein, created from `deploy/cloud-init.yml`,
which installs Docker, keeps the system patched, and blocks the containers from reaching
private address ranges and the cloud metadata address. Scans leave from 162.55.43.236
and 2a01:4f8:c016:78c3::1.

Follow `operations.md`. The values for this domain, in `deploy/.env`:

```sh
SITE_ADDRESS=perimeterwatch.org
ACME_EMAIL=security@perimeterwatch.org
PW_BASE_URL=https://perimeterwatch.org
PW_CONTACT_URL=https://perimeterwatch.org
PW_ABUSE_EMAIL=abuse@perimeterwatch.org
PW_MAIL_FROM=Perimeterwatch <no-reply@perimeterwatch.org>
PW_SCAN_SOURCES=["162.55.43.236","2a01:4f8:c016:78c3::1"]
PW_SECURITY_EMAIL=security@perimeterwatch.org
PW_CONTACT_EMAIL=hello@perimeterwatch.org
```

Add `PW_SIGNUP_OPEN=false` to stop strangers creating accounts. It is left open during
the beta so that pilot organisations can join.

Then point the domain at the server:

| Type | Name | Value | Proxy |
|---|---|---|---|
| A | `@` | the server's address | **DNS only** (grey cloud) |

Use "DNS only". With Cloudflare's proxy on, the bundled proxy cannot obtain its own
certificate in the usual way, and visitors' addresses in the audit log would be
Cloudflare's. If you want Cloudflare in front later, that is a separate piece of work.

### Where scan traffic comes from

Scans leave from the server's own address. Publish that address on the page at
`PW_CONTACT_URL`, so organisations can recognise the scanner in their logs.

Block outbound traffic from the worker to private address ranges and to
169.254.169.254 at the server's firewall, as `operations.md` explains.

## Step 5: the page at perimeterwatch.org

`PW_CONTACT_URL` is sent with every request the scanner makes. Someone who finds the
scanner in their logs will open it. The page should say, briefly:

- what Perimeterwatch is, and that it scans only domains whose owners asked;
- the address scans come from;
- how to ask for scans of a host to stop (`abuse@perimeterwatch.org`), and that the
  request is honoured by adding the host to a list no scan will contact;
- how to report a vulnerability in the service.

The service serves this page at `/` to visitors who are not signed in. Set
`PW_SCAN_SOURCES` to the server's addresses so the page can show them, and
`PW_SECURITY_EMAIL` so the service answers `/.well-known/security.txt`. The legal drafts
are served at `/legal`.

## Step 6: check the result

```sh
uv run pwatch scan perimeterwatch.org --probe
uv run pwatch diff perimeterwatch.org
```

The findings from the sample report should be listed as resolved. Copy the new report into
`docs/sample-report/` so that the published sample shows a change being detected.

## Order of work

1. DNSSEC and CAA (step 1). Ten minutes, free.
2. Email routing and a DMARC record (step 2). Twenty minutes, free.
3. Verification record and an active scan of the empty domain (step 3).
4. Rescan and publish the second sample report (step 6).
5. Server, deployment and the contact page (steps 4 and 5), when there is a server to use.
