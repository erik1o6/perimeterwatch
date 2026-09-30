# Sample report

A real report, made by scanning the project's own domain, `perimeterwatch.org`.

- Read it on the site: <https://perimeterwatch.org/sample-report>
- The same findings for other tools: <https://perimeterwatch.org/sample-report.json>. The
  format is in [`../report.schema.json`](../report.schema.json).
- The files are kept in the package, so the service can serve them:
  [`report.html`](../../src/perimeterwatch/web/sample/report.html) and
  [`report.json`](../../src/perimeterwatch/web/sample/report.json).

## What it shows

The scan ran at probe depth on 30 September 2026, the day after the domain was registered
and the day the service went live. It is the second report of the domain, so it shows the
part of Perimeterwatch that matters most: what changed since last time.

| Change | Finding |
|---|---|
| Resolved | No DMARC record. One was published |
| Resolved | No SPF record. One was published |
| Resolved | No CAA record. Three were published |
| New, medium | The DKIM key of the mail service is only 1024 bits long |
| New, low | The SPF record only soft-fails unlisted senders |
| New, low | No MTA-STS policy |
| New, info | The scripts the site serves, recorded so that a change is noticed |
| New, info | Where to report security problems, read from `security.txt` |
| Changed | The list of outside services the domain relies on |

Still open from the first report: the domain is not yet signed with DNSSEC, and it has a
registrar lock but no registry lock.

Checks that need a GitHub organisation, a Safe, packages or a verified domain did not run.
The "Coverage" section of the report lists each one and why.
