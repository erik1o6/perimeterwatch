# Perimeterwatch: paste-ready submission

Text for the form at https://initiatives.thedao.fund/submit, in the order the form asks for it. The same text, laid out for reading, is in `10-resubmission.md`. The two files carry the same wording.

The form was read on 30 September 2026. It has changed since the first submission of 9 September: a grant now has the sections "The team", "Why a grant: what already exists" and "Commitments", and the site adds the process and review rules itself.

## How to paste

1. Connect the wallet, sign in, and set the name and picture. They are shown in public with the initiative, so use the ones that belong to code2142.
2. Set the two fields under "By hand, before pasting".
3. Open this file as plain text, so that the `##` headings come along. Copy everything between the two rules under "The paste block", from `## Title` to the last milestone criterion, and paste it into the box labelled "Your whole draft as one text". The form sorts it into its fields. The "Unsorted text" box should stay empty.
4. Check what the form read: the goal shows $150,000, the four milestone amounts total $150,000, and "Verified adoption" is flagged as the adoption milestone.
5. Fill the fields under "By hand, after pasting". Two of them are private and are not written in this file, because this file is public.
6. Use the form's preview, then submit.

## Short texts

One-sentence tagline. The form has no field for it. Use it wherever a one-line description is wanted.

> Perimeterwatch shows an Ethereum project what any outsider can already find out about its systems, and warns the project when that changes.

One-paragraph summary, 66 words. This is the text of the "Short summary" field below, which the fund shows on the board card.

> Perimeterwatch is a free, open-source service that shows an Ethereum project what any outsider can already find out about its domains, email, public code, contracts and multisigs, and warns it when that changes. A project proves control of its domain and gets a private report, each finding with a fix. It runs in beta at perimeterwatch.org. This grant hardens it and brings 25 organisations onto it.

## By hand, before pasting

### By hand: Type

Grant

### By hand: Work is already under way with another funder

Leave unticked. No other funder pays for this work.

## The paste block

**Copy from the line after the rule below.**

---

## Title

Perimeterwatch: Private External Exposure Monitoring for Ethereum Projects

## Short summary

Perimeterwatch is a free, open-source service that shows an Ethereum project what any outsider can already find out about its domains, email, public code, contracts and multisigs, and warns it when that changes. A project proves control of its domain and gets a private report, each finding with a fix. It runs in beta at perimeterwatch.org. This grant hardens it and brings 25 organisations onto it.

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
https://github.com/erik1o6/perimeterwatch/tree/main/docs/sample-report

## Why this matters

Perimeterwatch is a free service that shows an Ethereum project what any outsider can already find out about its systems, and warns the project when that changes. It is for teams that have no security staff of their own.

Many losses now start outside the smart contracts. Attackers took over the balancer.fi domain in September 2023 and drained about $238,000 from visitors ([Balancer post mortem](https://medium.com/balancer-protocol/dns-security-incident-post-mortem-1b1feb735aca)). The Aerodrome and Velodrome domains were hijacked in November 2025 ([CoinDesk](https://www.coindesk.com/web3/2025/11/22/aerodrome-finance-hit-by-front-end-attack-users-urged-to-avoid-main-domain)), and early onchain estimates put visitors' losses above $1 million ([Bitcoin.com News](https://news.bitcoin.com/dns-attack-strikes-aerodrome-and-velodrome-as-aero-merger-nears/)). The facts an attacker uses to plan this are public but scattered, and commercial tools that gather them are priced for companies with security budgets.

A project adds one DNS record and gets a private list of its weak points, each with a fix:

- email settings that let anyone send mail in its name
- forgotten web addresses that someone else could claim
- a domain without a registry lock, or a change of registrar or nameservers
- credentials published by mistake in public code
- a change to its treasury signers, its Safe's modules, or who controls a contract
- a change to the scripts its website serves

Perimeterwatch reports exposure and change. It does not block an attack. It looks only at projects that ask, publishes nothing, and gives no score or rating.

## The team

**Perimeterwatch** is the recipient: a non-profit to be established, led in public by code2142, who submits under a pseudonym. No legal entity exists yet. Setting one up is in the budget.

code2142 built the prototype alone and will lead implementation, onboarding, review of findings and maintenance. The grant adds a developer and part-time operations support. code2142 is a security lead with more than ten years of experience, the last several spent running security for crypto organisations, including as head of security at a DeFi lending protocol. code2142 holds an ETHSecurity Badge from TheDAO Security Fund.

Track record: the public code and its history at https://github.com/erik1o6/perimeterwatch.

No other funder pays for this work, and $0 is committed against the $150,000 goal. code2142 wrote the Perimeterwatch code and has no co-authors. There is no companion initiative.

## Why a grant: what already exists

The first version of this submission (xWatch, 9 September 2026) claimed no prototype. One now exists, and a stranger can check it:

- **Live beta.** https://perimeterwatch.org has run since 30 September 2026 on one server in Germany, over HTTPS. Sign-up is open. Sign-in by emailed link, proof of domain control, scheduled scans, alerts and an audit log work. The home page lists the checks that run today, the addresses scans come from, and how the operator of a scanned host asks to be left alone.
- **Public code.** https://github.com/erik1o6/perimeterwatch, under Apache-2.0: 34 checks at three depths (passive, probe, active), 104 kinds of finding, and 10 third-party tools pinned by version and verified by checksum, among them subfinder, nuclei and trufflehog. 33 of the checks run in the beta today.
- **Tests.** 2,555 automated tests pass in public CI on every change. One test file tries every route of the web service as a different organisation and confirms that nothing leaks.
- **Sample report.** https://github.com/erik1o6/perimeterwatch/tree/main/docs/sample-report, from a scan of the project's own domain.
- **Draft legal documents.** https://perimeterwatch.org/legal, each marked as a draft.

What the prototype is not:

- Only the maintainer's own domains are monitored. No outside organisation relies on it.
- No independent security review has been done.
- No lawyer has reviewed the legal drafts.
- There is no paid data subscription. The breach check is built and switched off.
- There is one maintainer and no legal entity yet.

Work done before the funded phase is not charged to this grant. The $150,000 buys review, a data licence, six months of operation and the onboarding of 25 organisations. The engine and the service already exist.

## In scope

The grant pays to turn the beta into a service that other organisations can rely on, and to get them onto it.

- Hardening and operating the service for six months: backups with a tested restore, monitoring, the fixes from the security review, and the onboarding flow (inviting colleagues, uploading a staff list, closing an account).
- An independent security assessment and retest. The service stores a map of each participant's weak points.
- A lawyer's review of the terms, privacy policy and data processing agreement.
- A licensed source of breach data for one year. Have I Been Pwned is the planned source. Intelligence X, which the first submission named, is the alternative. The choice is made once a supplier confirms in writing that use by a hosted service for several organisations is allowed.
- Breach findings for work email addresses from a list the project supplies. The service does not collect staff identities from professional networking sites, because of the legal risk. This is narrower than the first submission on purpose.
- Scheduled monitoring: alerts on change, a source and a certainty label on each finding, and human review of high-risk or uncertain findings.
- Onboarding at least 25 external Ethereum organisations (registered organisations, DAOs and unincorporated teams), starting with code2142's existing contacts and security-partner referrals.
- A developer and part-time operations support, setting up the non-profit, and the independent milestone reviewer's fee.

Budget allocations are planning estimates, not signed supplier quotes. Indicative timing from the start of funding: hardened service by the end of month 2, breach monitoring and legal review by month 3, adoption by month 5, close-out in month 6.

## Out of scope

- Publishing findings or assessments about a project without its explicit approval.
- A public rating. The OPSEC Ratings Coalition initiative covers that. Perimeterwatch reports follow a published JSON schema, so a rating effort can read them with the project's consent.
- Task tracking, training and compliance mapping, which the "A Unified Platform for Web3 OpSec" initiative on this board covers. It can import the same reports.
- Monitoring personal accounts without the person's explicit consent.
- Collecting information about individuals from social media or professional networks.
- Testing credentials that are found, or attempting to exploit anything.
- Remediation, incident response, smart contract audits or penetration testing for participants.
- Promises of exhaustive discovery, perfect identity verification, or unlimited capacity at fixed cost.
- Charging this grant for work already completed in the prototype.

## Commitments

- **Licence.** Platform code stays public under Apache-2.0, with deployment instructions. Participant records, provider credentials and licensed data stay out of the repository.
- **Verified access.** Nothing is scanned until the project proves control of its domain with a DNS record, which is checked again before every scan. Removing the record withdraws access. Before an organisation counts toward adoption, a person also confirms the requester's authority, using documented governance or established leadership for a DAO or an unincorporated team.
- **Private findings.** Only a project's authorised users see its findings. Details about individual people are shown only while the domain is verified, and each view is logged.
- **Safe scanning.** Hosts at private addresses and lookalike domains are never contacted. Beyond the project's own hosts, a scan asks only the domain's nameservers and the storage buckets its DNS points at. Every request names the scanner and gives a contact address. A host whose operator asks is put on a list that no scan will contact.
- **Review before adoption.** The beta is open and states that it has had no independent review. No organisation is recruited, and none counts toward adoption, until the independent assessment and retest report is published.
- **Pinned targets.** At least 25 external Ethereum organisations monitored and at least 30 findings fixed. Amounts and targets are fixed as submitted.
- **Maintenance.** code2142 and Perimeterwatch maintain the service. Sponsorships, donations and further grants are the preferred funding. Operation after month 6 depends on further funding. If outside funding cannot cover costs, organisations with more than 20 founders, employees and regular contractors get a free month, keep their report, and pay for monitoring after that. The fee and the condition that triggers it are published before any charge.
- **Exceptions.** None requested.

## Milestones

### Hardened service, ready for outside organisations - $30,000

- [ ] An independent security assessment and retest report on the service and its separation between organisations is published, with every critical and high finding fixed and confirmed by the assessor.
- [ ] A public test report shows a backup restored into an empty deployment, a monitoring alert reaching the maintainers, and refusal of access across organisations and of scans of unverified domains.
- [ ] Version 1.0 is tagged in the public repository with colleague invitations, staff list upload and account closure, and its release notes separate funded work from work done before the grant.
- [ ] The technical reviewer confirms that the site stated the service had no independent review until the assessment report was published, and that the adoption count started after that date.

### Breach monitoring and legal review - $30,000

- [ ] A public integration report confirms that the licensed breach source runs in production and states permitted use and coverage, and the technical reviewer has seen the supplier's written permission to serve several organisations.
- [ ] The terms of service, privacy policy and data processing agreement are published as reviewed by a qualified lawyer, and the technical reviewer has seen the lawyer's letter naming them.
- [ ] A public test report shows scheduled rescans, a changed test record producing a private alert, and the human-review workflow for high-risk or uncertain findings.

### Verified adoption - $75,000 (adoption)

- [ ] At least 25 external Ethereum organisations, each with contracts or a Safe on Ethereum or an L2, have verified a domain, received an initial report and received at least 4 scheduled updates after the assessment report was published, attested in public by the technical reviewer from private production records. Demonstrations, internal pilots and the team's own domains do not count.
- [ ] At least 30 findings have been fixed by those organisations, each shown by a later completed scan that no longer reports it, as counted by the technical reviewer.
- [ ] A public adoption page gives the verified count, the counting method and the reviewer's attestation. It names an organisation only with that organisation's explicit approval and shows no findings.

### Continued operation and maintenance - $15,000

- [ ] A public end-of-phase report documents the monitoring delivered through month 6, source coverage, limitations and release history, without participant identities or findings.
- [ ] A published maintenance plan names code2142 and Perimeterwatch, assigns ongoing responsibilities, and states the recurring operating costs and the funding needed after month 6.
- [ ] A public access policy states free service while externally funded, the more-than-20-person threshold, the free month and retained report for larger organisations, the price of monitoring after that, and the funding-shortfall condition that activates charges.

---

**Stop copying at the line above the rule.**

Notes on the block:

- The form's label for the "Links" field is "Other links". The pasted heading must be "Links" for the form to sort it.
- "Backers already committed" is left out on purpose. Nobody has committed money.
- The form letters the milestones A to D itself.

## By hand, after pasting

### By hand: Recipient link

https://perimeterwatch.org

### By hand: Discussion link

Optional. Leave it empty unless there is a public thread about this initiative to link.

### By hand: Who is likely to fund this? (private, never published)

Not written here, because this file is public. The form wants one funder per line, in this shape:

`name | why they care | your relationship | warm intro? | likely amount`

The candidates and the state of each conversation are for the maintainer to fill in. `07-cofunding.md` lists the kinds of organisation that benefit and why.

### By hand: Contact (private, never published)

Not written here, because this file is public. The form wants an email address or a handle for questions about the submission. Use a contact that belongs to the pseudonym code2142 or to the project.
