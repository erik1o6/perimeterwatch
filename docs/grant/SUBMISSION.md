# Perimeterwatch: paste-ready submission

Text for the form at https://initiatives.thedao.fund/submit, written to the fund's drafting guide (rules dated 17 September 2026). The same text, laid out for reading, is in `10-resubmission.md`.

## How to paste

1. Connect a wallet, sign in, and set the name and picture. They are shown in public with the initiative, so use ones that belong to code2142 and to nobody else.
2. Choose the type **Grant**. Leave "Work is already under way with another funder" unticked.
3. Open this file as plain text, so that the `##` headings come along. Copy everything between the two rules below, from `## Title` to the last milestone criterion, and paste it into the box labelled "Your whole draft as one text". The form sorts it into its fields. The "Unsorted" box should stay empty.
4. Check what the form read: the goal shows $150,000, the four milestone amounts total $150,000, and "Verified adoption" is flagged as the adoption milestone at $75,000 (50%).
5. Type the recipient link by hand: https://perimeterwatch.org
6. Fill the two private fields, "Who is likely to fund this?" and "Contact". They are not in this file, because this file is public.
7. Use "See it as a page", then submit.

## The two prices the reviewer will work out

- The adoption milestone: $75,000 for 25 organisations is $3,000 each, and $7,500 for each of the 10 that secure over $1 million onchain.
- The whole grant: $150,000 for 25 monitored organisations is $6,000 each.

## The paste block

**Copy from the line after the rule below.**

---

## Title

Perimeterwatch: Private External Exposure Monitoring for Ethereum Projects

## Short summary

Perimeterwatch is a free, open-source service that shows an Ethereum project what any outsider can already find out about its domains, email, public code, contracts and multisigs, and warns it when that changes. A project proves control of its domain and gets a private report, each finding with a fix. It runs in beta at perimeterwatch.org. This grant pays for an independent security review and brings 25 organisations onto it.

## Categories

OpSec
Detection & Response

## Funding goal (USD)

$150,000

## Expected duration (months)

6

## Recipient team

Perimeterwatch

## Links

https://perimeterwatch.org
https://github.com/erik1o6/perimeterwatch
https://perimeterwatch.org/sample-report

## Why this matters

Small Ethereum teams with no security staff end up safer from attacks that start outside their contracts: a hijacked domain, a swapped website script, a leaked credential, a quietly changed treasury signer.

Attackers took over the balancer.fi domain in September 2023 and drained about $238,000 from visitors ([Balancer post mortem](https://medium.com/balancer-protocol/dns-security-incident-post-mortem-1b1feb735aca)). The Aerodrome and Velodrome domains were hijacked in November 2025 ([CoinDesk](https://www.coindesk.com/web3/2025/11/22/aerodrome-finance-hit-by-front-end-attack-users-urged-to-avoid-main-domain)), and early onchain estimates put visitors' losses above $1 million ([Bitcoin.com News](https://news.bitcoin.com/dns-attack-strikes-aerodrome-and-velodrome-as-aero-merger-nears/)). The facts an attacker uses to plan this are public but scattered, and the commercial tools that gather them are priced for companies with security budgets.

A project adds one DNS record. It gets a private list of its weak points, each with a fix, and an alert when a new one appears:

- email settings that let anyone send mail in its name
- forgotten web addresses that someone else could claim
- a domain without a registry lock, or a change of registrar or nameservers
- credentials published by mistake in public code
- a change to its treasury signers, its Safe's modules, or who controls a contract
- a change to the scripts its website serves
- systems named in its own job postings, which tell an attacker what it runs

Perimeterwatch reports exposure and change. It does not block an attack. It looks only at projects that ask, publishes nothing, and gives no score.

## The team

**Perimeterwatch** is the recipient: a non-profit to be established, led in public by code2142. No legal entity exists yet. Setting one up is in the budget.

code2142 built the prototype alone and will lead implementation, onboarding and maintenance. The grant adds a developer and part-time operations support. code2142 is a security lead with more than ten years of experience, the last several spent running security for crypto organisations, including as head of security at a DeFi lending protocol, and holds an ETHSecurity Badge from TheDAO Security Fund.

Track record: the public code and its history at https://github.com/erik1o6/perimeterwatch.

No other funder pays for this work. code2142 wrote the Perimeterwatch code, has no co-authors, and has no relationship with Have I Been Pwned or Intelligence X, the data suppliers named below. There is no companion initiative.

## Why a grant: what already exists

The first version of this submission (xWatch, 9 September 2026) had no prototype. One now exists, and a stranger can check it:

- **Live beta.** https://perimeterwatch.org has run since 30 September 2026 on one server in Germany. Sign-up, proof of domain control, scheduled scans, alerts and an audit log work.
- **Public code.** Apache-2.0: 34 checks at three depths, 104 kinds of finding, and 10 third-party tools pinned by version and checksum. 33 of the checks run in the beta.
- **Tests.** 2,560 automated tests pass in public CI on every change.
- **Sample report.** https://perimeterwatch.org/sample-report, from a scan of the project's own domain.
- **Draft legal documents.** https://perimeterwatch.org/legal.

What it is not: only the maintainer's own domains are monitored, no independent security review has been done, no lawyer has reviewed the legal drafts, and the breach check is built but switched off because its data costs money.

The engine and the service are not charged to this grant. The $150,000 buys review, a data licence, six months of operation and the onboarding of 25 organisations.

## In scope

- An independent security assessment and retest of the service, which stores a map of each participant's weak points.
- Hardening and operating the service for six months: backups with a tested restore, monitoring, and the missing parts of the onboarding flow (inviting colleagues, uploading a staff list, closing an account).
- A lawyer's review of the terms, privacy policy and data processing agreement.
- A licensed source of breach data for one year. Have I Been Pwned is the planned source: its Pro 1 plan costs $379 a month, $4,548 a year, for up to 50 domains. Intelligence X is the alternative: its Identity Portal plan costs about $11,400 a year, converted from the supplier's euro price at the European Central Bank's rate of 30 September 2026. The choice is made once a supplier confirms in writing that a hosted service may use the data for several organisations.
- Breach findings for work email addresses from a list the project supplies, with human review of high-risk or uncertain findings.
- Onboarding at least 25 external Ethereum organisations, starting with code2142's contacts and referrals from security firms.
- A developer and part-time operations support, setting up the non-profit, and the independent technical reviewer's fee.

Budget allocations are planning estimates, not supplier quotes.

## Out of scope

- Publishing findings about a project without its approval, or any public rating. The OPSEC Ratings Coalition initiative covers ratings. Perimeterwatch reports follow a published JSON schema, which a rating effort can read with the project's consent.
- Collecting information about individuals from social media or professional networks. This is narrower than the first submission on purpose.
- Testing credentials that are found, or attempting to exploit anything.
- Remediation, incident response, smart contract audits or penetration testing for participants.
- Any chain outside Ethereum and its L2s.

## Commitments

- **Licence.** Platform code stays public under Apache-2.0, with deployment instructions.
- **Maintenance.** code2142 and Perimeterwatch maintain the service. Operation after month 6 depends on further funding: sponsorships, donations and grants first. If those fall short, organisations with more than 20 people get a free month, keep their report, and pay for monitoring after that. The fee and its trigger are published before any charge.
- **Pinned targets.** At least 25 external Ethereum organisations monitored, at least 10 of them securing over $1 million onchain, and at least 30 findings fixed.
- **Review before adoption.** The beta is open and states that it has had no independent review. Organisations may join it, and none counts toward adoption until the assessment and retest report is published. Before an organisation counts, a person confirms that the requester has authority to act for it.
- **Safeguards.** Nothing is scanned until a project proves control of its domain by DNS record, which is checked again before every scan. Only a project's own users see its findings. Private addresses and lookalike domains are never contacted, and a host whose operator asks is put on a list that no scan will contact.
- **Adoption page.** A public page gives the verified count and the reviewer's attestation. An organisation is named only with its approval, and no findings are shown.
- **Exception requested.** The recipient is pseudonymous in public. code2142 will identify themselves to TheDAO Security Fund in private.

## Milestones

### Hardened service - $30,000

- [ ] Version 1.0 is tagged in the public repository with colleague invitations, staff list upload and account closure.
- [ ] A public test report shows a backup restored into an empty deployment and a monitoring alert delivered, confirmed by the technical reviewer.

### Security assessment, breach monitoring and legal review - $30,000

- [ ] An independent security assessment and retest report is published, with every critical and high finding confirmed fixed by the assessor.
- [ ] The licensed breach source runs in production, and the technical reviewer has seen the supplier's written permission to serve several organisations.
- [ ] The terms of service, privacy policy and data processing agreement are published as reviewed by a lawyer, and the technical reviewer has seen the lawyer's letter.

### Verified adoption - $75,000 (adoption)

- [ ] At least 25 external Ethereum organisations have verified a domain and received at least 4 scheduled reports since the assessment report was published, counted by the technical reviewer from production records under confidentiality.
- [ ] At least 10 of those organisations each secure over $1 million onchain in a Safe or in contracts on Ethereum or an L2, measured by the technical reviewer from onchain balances.
- [ ] At least 30 findings have been fixed by those organisations, each shown by a later scan that no longer reports it, counted by the technical reviewer.

### Continued operation and maintenance - $15,000

- [ ] A public end-of-phase report covers six months of monitoring, source coverage and limitations, with no participant identities or findings.
- [ ] A published maintenance plan names the maintainers, the recurring costs and the funding needed after the grant.

---

**Stop copying at the line above the rule.**

Notes on the block:

- "Backers already committed" is left out on purpose. Nobody has committed money yet.
- The form letters the milestones A to D itself.
- The form fields hold about 1,430 words. The fund's guide asks for under 1,200 for an ask above $50,000. Nothing in the form enforces it.
