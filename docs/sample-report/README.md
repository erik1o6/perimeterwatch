# Sample report

A real report, made by scanning the project's own domain, `perimeterwatch.org`.

- [`report.html`](report.html): the report as a person reads it. Download it and open it in a browser.
- [`report.json`](report.json): the same findings for other tools to read. Its format is in [`../report.schema.json`](../report.schema.json).

## What it shows

The scan ran at probe depth on 29 September 2026, the day the domain was registered. The domain had no web or mail records yet, so the report is short, and its findings are those of any fresh registration:

| Severity | Finding |
|---|---|
| High | No DMARC record, so mail claiming to come from the domain is not rejected |
| Medium | No SPF record |
| Low | No CAA record |
| Low | Not signed with DNSSEC |
| Info | Registration details, recorded so that a change of registrar or nameservers is noticed |
| Info | All nameservers are with one provider |

Checks that need a GitHub organisation, a Safe, packages or a verified domain did not run. The "Coverage" section of the report lists each one and why.

## What comes next

These findings will be fixed as the domain is set up for the service. The next report will then list them under "Resolved", which is the part of Perimeterwatch that matters most: it tells you what changed since last time.
