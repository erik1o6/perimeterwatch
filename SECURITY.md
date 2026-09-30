# Security policy

This file covers vulnerabilities in the Perimeterwatch software: the `perimeterwatch` command-line tool and the scanning engine.

## Reporting a vulnerability

Please report privately. Do not open a public issue for a security problem.

| | |
|---|---|
| Email | security@perimeterwatch.org |
| Private report through the repository host | Not switched on. Use the email address |
| Encryption key | None. Reports go by plain email |

Please include:

1. What the problem is and where in the code.
2. Steps to reproduce it.
3. What an attacker could do with it.
4. The version you tested (`pwatch --version`) and how you installed it.

Please do not include real credentials or personal data of other people.

We aim to acknowledge a report within 3 working days. The project has one maintainer, so this is a target and not a guarantee.

## Supported versions

| Version | Supported |
|---|---|
| The `main` branch | Yes |
| Anything older | No |

The project has not yet made a stable release. Until it does, fixes are made on the main branch only.

## Problems we especially want to hear about

- Contact with a host outside the scanned domain, or with a private or reserved address.
- Active checks running without authorisation.
- Findings about individual people shown for a domain that is not verified.
- Domain verification passing without control of the domain's DNS.
- A found credential being stored, shown in full, logged or tested.
- A request other than a plain GET or HEAD being sent during exposure checks.
- Command or argument injection through a host name, DNS answer, repository content or tool output.
- Stored findings or staff addresses readable without the encryption key.

## Full policy

The full draft policy, including scope, safe harbour, response targets and what not to do, is in [src/perimeterwatch/legal/vulnerability-disclosure.md](src/perimeterwatch/legal/vulnerability-disclosure.md). That document is a draft and has not yet had legal review.

## Not a security report

If you operate a host that received traffic from a Perimeterwatch scan and you want it to stop, see [src/perimeterwatch/legal/opt-out.md](src/perimeterwatch/legal/opt-out.md).
