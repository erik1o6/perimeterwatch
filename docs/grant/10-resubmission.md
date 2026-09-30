> Draft for review and editing. Not yet submitted.
>
> This follows the structure of the original xWatch submission of 9 September 2026. Lines
> marked **[DECIDE]** are choices for the maintainer. The notes at the end explain each one
> and list what changed from the original.

# Grant: Perimeterwatch: Private External Exposure Monitoring for Ethereum Projects

The first version of this submission was called xWatch. The project is now called Perimeterwatch, and lives at perimeterwatch.org.

| | |
|---|---|
| **Status** | Draft |
| **Budget** | $150,000 USD |
| **Proposal window** | 15 days, opening once the grant is fully funded |
| **Indicative duration** | 6 months (the recipient sets the final timeline) |
| **Working prototype** | https://github.com/erik1o6/perimeterwatch |
| **Sample report** | https://github.com/erik1o6/perimeterwatch/tree/main/docs/sample-report |

## Why this matters

Perimeterwatch is a free service that shows an Ethereum project what any outsider can already find out about its systems, and warns the project when that changes. It is for teams that have no security staff of their own.

A project proves that it controls its domain, and from then on receives a private report of its weak points, each with a fix. Examples: settings that let anyone send email in the project's name, forgotten web addresses that someone else could claim, credentials published by mistake in public code, a change to who can sign for the treasury, a change to the scripts its website serves, and staff email addresses found in known breaches.

Most losses in this ecosystem now start outside the smart contracts: a hijacked domain, a compromised website, an infected laptop. The information an attacker uses to plan these is public, but it is scattered, and small teams never see it in one place. Commercial tools that gather it cost tens of thousands of dollars a year.

Perimeterwatch only looks at projects that ask. It publishes nothing, and it gives no score or rating. The platform is open source, and access is paid for by ecosystem funding. No funding commitments have been reported: $0 is committed against the $150,000 goal.

## What this actually pays for

A working prototype exists and is public. This grant does not pay for it. The grant pays for turning it into a service that other organisations can rely on, and for getting them onto it.

The six-month programme funds:

- A first production deployment, and its operation for participating projects.
- An independent security assessment and retest. The service will hold a map of the weak points of every project that uses it, so it must be reviewed before any outside project is taken on.
- Legal review of the terms, privacy policy and data processing agreement, which exist as drafts.
- A licensed source of breach data. **[DECIDE: which source. See the notes.]** The prototype uses no paid subscription of any kind. The budget covers a full year's licence. Supplier pricing, allowances and permission to serve several organisations will be confirmed in writing before purchase.
- A developer and part-time operations support alongside code2142's leadership.
- Setting up and administering the non-profit.
- Onboarding projects, which is half of the budget.
- Independent milestone review.

Budget allocations are planning estimates, not signed supplier quotes.

## The recipient

The proposed recipient is Perimeterwatch, a non-profit to be established, led publicly by code2142. code2142 developed the concept, built the prototype, and will lead implementation, onboarding, review of findings, and maintenance, supported by the funded developer and operations role. Initial participants will be recruited through code2142's existing contacts and security-partner referrals.

code2142 is a security lead with more than ten years of experience, the last several spent running security for crypto organisations, including as head of security at a DeFi lending protocol. code2142 holds an ETHSecurity Badge from TheDAO Security Fund.

**Why a grant and not an RFP.** The previous version of this submission did not claim a prototype. This one does, and it can be checked:

- The code is public under the Apache-2.0 licence.
- It has 34 checks at three depths, a command-line tool, and a web service with sign-in, separation between organisations, domain verification, scheduled scans, alerts and an audit log.
- 1,422 automated tests pass in public on every change, including tests against Postgres and a build of the container image.
- One test file tries every route of the web service as a different organisation and confirms that nothing leaks.

What the prototype is not: it has never been deployed for anyone, no outside person has reviewed it, and no organisation uses it. Those are what the grant pays for.

Work completed before the funded phase will not be charged to this grant. There are no co-authors or companion initiatives identified.

Every applicant, including any expected recipient, must disclose their relationships to the teams, codebases, and firms named in this initiative.

## Existing work

Perimeterwatch builds on existing open-source tools and does not rewrite them. Each is a separate program that Perimeterwatch downloads at a pinned version, verifies against a recorded checksum, and runs.

| Purpose | Tool | Licence |
|---|---|---|
| Finding hostnames | subfinder, crt.sh | MIT |
| Web servers, certificates, TLS settings | httpx, tlsx | MIT |
| Open ports | naabu | MIT |
| Known exposures | nuclei, restricted to read-only checks | MIT |
| Credentials in public code | trufflehog, Betterleaks | AGPL-3.0, MIT |
| SSH server settings | ssh-audit | MIT |
| Storage buckets | S3Scanner | MIT |
| Email protection | checkdmarc | Apache-2.0 |
| Lookalike domains | dnstwist | Apache-2.0 |

These are existing work by their maintainers. What Perimeterwatch adds is the part none of them has: consent and proof of domain control, separation between organisations, comparison of each scan with the last, alerts, and the rules that keep scanning within safe limits.

Public platform code excludes provider credentials and restricted source data.

## Scope

**In scope**

- Opt-in participation by registered organisations, DAOs, and unincorporated Ethereum teams, with proof of control of the project's domain and verification of the requester's authority.
- Mapping a project's domains, subdomains, public infrastructure, public code, published packages, contracts and multisigs.
- Work email addresses, from a list the project supplies. **[DECIDE: the original also included founders, employees and contractors found through public professional profiles. See the notes.]**
- Private exposure reports combining public information, records the project supplies, and authorised breach-monitoring sources.
- Scheduled monitoring, alerts when something changes, source and certainty labels, priorities, and guidance on fixing each finding. High-risk or uncertain findings receive human review.
- Recruitment and operation for at least 25 external Ethereum organisations.

**Out of scope**

- Publishing findings or assessments about a project without its explicit approval. A public OPSEC rating system is not part of this grant. Perimeterwatch's reports can be read by other tools, so a rating effort could use them as one input with the project's consent.
- Monitoring personal accounts without the person's explicit consent.
- Collecting information about individuals from social media or professional networks.
- Testing credentials that are found, or attempting to exploit anything.
- Performing remediation, incident response, smart contract audits or penetration testing for participating projects.
- Promising exhaustive discovery, perfect identity verification, or unlimited capacity at fixed cost.
- Charging for work already completed in the prototype.

## Hard requirements

1. **Verified access.** Nothing is scanned until the project proves control of its domain with a DNS record. The proof is checked again before every scan, and removing the record withdraws access. Every organisation also requires manual approval, with confirmation of the requester's authority. DAOs and unincorporated teams use documented verification of project governance or established leadership.
2. **Private findings.** Only authorised recipients can see a project's findings. Details about individual people are shown only while the domain is verified, and each view is recorded. Public demonstrations use made-up records.
3. **Open-source platform.** Platform code is published under an OSI-approved licence with deployment instructions. Participant records, provider credentials and restricted licensed data stay outside the public repository.
4. **Scheduled coverage.** The funded service provides exposure mapping, private reports, scheduled monitoring, and integration of the licensed breach source. Findings state their source and how certain they are.
5. **Safe scanning.** Hosts outside the project's domain are never contacted, nor hosts at private addresses, nor lookalike domains. Anyone whose host receives traffic can ask for it to stop, and is added to a list that no scan will contact. Every request identifies the scanner and gives a contact address.
6. **Independent security assessment.** The service and its separation between organisations undergo an independent assessment and retest before any outside project is onboarded. Public evidence records the scope, status of findings and fixes, without exposing participant information.
7. **Verified adoption.** At least 25 external Ethereum organisations must verify a domain, receive an initial report, and each receive at least four scheduled updates. An independent reviewer verifies production evidence privately and publishes the aggregate count and counting method. Names are published only with explicit approval. This evidence method will be agreed with Giveth in the grant agreement.
8. **Maintenance and funding.** code2142 and Perimeterwatch maintain the service. Sponsorships, donations and further grants are the preferred funding sources. Continued operation after month 6 depends on further funding. If external funding cannot cover costs, organisations with more than 20 founders, employees and regular contractors receive a free month, keep their report, and pay for monitoring after that. The fee and the condition that triggers it must be published before charges begin.

## Milestones (draft)

These milestones are a draft. Final milestones and payments get negotiated with the winning team and fixed in the grant agreement. If you think this draft is wrong, tell us how in your proposal... improving it is part of winning.

The indicative targets are the end of month 2 for milestone 1, month 3 for milestone 2, month 5 for milestone 3, and month 6 for milestone 4. Months run from the start of the funded phase. **The $75,000 adoption payment is 50% of the total budget.**

### 1 - Production service - $30,000

- [ ] A tagged 1.0 release is published under an OSI-approved licence. Release notes distinguish funded improvements from work done before the grant.
- [ ] The service is deployed from the published instructions and reachable at a public address. Scans leave from a fixed, published address.
- [ ] A public sample report, made from a domain the team owns, shows every kind of finding.
- [ ] A public test report demonstrates manual approval, proof of domain control, refusal to scan an unverified domain, and rejection of access across organisations.
- [ ] A published data-handling policy, reviewed by a lawyer, specifies consent, access permissions, retention and deletion.

### 2 - Breach monitoring and security review - $30,000

- [ ] A public integration report confirms that the licensed breach source is integrated in production, and documents permitted use and coverage without exposing licensed records or credentials. The supplier's written permission to serve several organisations is on file.
- [ ] A public test report demonstrates scheduled rescans, a changed test record producing a private alert, and the human-review workflow for high-risk or uncertain findings.
- [ ] A public independent assessment and retest report covers the service and its separation between organisations, documenting findings and the status of fixes without disclosing participant information or sensitive exploit details.
- [ ] No outside organisation has been onboarded before this report is published.

### 3 - Verified adoption - $75,000

- [ ] A public independent attestation confirms that at least 25 verified external Ethereum organisations have verified a domain, received an initial report, and each received at least four scheduled updates. Verification uses private production records. Demonstrations and internal pilots do not count.
- [ ] At least **[DECIDE: number, suggested 30]** findings have been fixed by those organisations, shown by a later scan no longer reporting them.
- [ ] A public adoption page publishes the verified count, counting method and independent attestation. Participant identities appear only with explicit approval; findings are excluded entirely.

### 4 - Continued operation and maintenance - $15,000

- [ ] A public end-of-phase report documents monitoring delivered through month 6, source coverage, limitations and release history, excluding participant identities and findings.
- [ ] A published maintenance plan names code2142 and Perimeterwatch, assigns ongoing responsibilities, and states recurring operating costs and the funding needed after month 6.
- [ ] A public access policy specifies free service when externally funded, the more-than-20-person threshold, the free month and retained report for larger organisations, the price of monitoring after that, and the funding-shortfall condition that activates charges.

## Milestone review and acceptance

- Criteria with objective public evidence (a live page, a published report, a named party confirming) are accepted on sight.
- Judgment calls are signed off by an independent technical reviewer with no ties to the selected team, agreed between Giveth and the team before work begins and named in the grant agreement.
- The reviewer's fee comes out of the milestone payment, or is pro bono. The winning team coordinates their payment.

## Process

- The proposal window opens once the grant is fully funded and stays open for 15 days. In that window, Perimeterwatch submits their formal proposal: the final milestone plan, per-milestone budget (the draft above, or a stronger version), and full disclosures. The window is also an open challenge period: anyone who can credibly deliver the same scope for the same money or less may submit a challenge.
- Giveth reviews within 7 days of the window closing and fixes the final plan in the grant agreement.
- Milestone deliveries are reviewed within 14 days; payment follows acceptance.
- The first milestone can be paid up to 50% in advance so the team has funding to start. If more funds are needed mid-milestone, the team is expected to reach out to the ecosystem for a stop-gap loan.
- If a milestone stalls, the team gets a 21-day deadline to complete it. If they miss it, TheDAO Security Fund reclaims the unspent funds and puts them toward other Ethereum security initiatives.

---

Questions, pushback, better ideas? Post them below.

---

## Notes for the maintainer (delete before submitting)

### How this answers the reviewer's three points

| Reviewer said | What changed |
|---|---|
| The summary did not say clearly what it is | "Why this matters" now opens with what it is and who it is for, then what a project gets, then why. The original opened with the gap. |
| No solid prototype, so it reads as an RFP | "The recipient" now points to public code, passing tests and a working web service, and says plainly what the prototype is not. |
| Make the adoption milestone 50% of the ask | Adoption is $75,000 of $150,000. It was $60,000 (40%). |

### Decisions

1. **Name.** Decided: Perimeterwatch. The submission says once that it was first called xWatch, so a reviewer who remembers the first version can connect the two.

2. **Breach data source.** The original required IntelX Identity Portal. The prototype is built on Have I Been Pwned.

   | | Have I Been Pwned Pro | IntelX Identity Portal |
   |---|---|---|
   | Price | About $4,500 a year for 50 domains | About €10,000 a year |
   | Serving other organisations | Allowed on Pro plans | Listed only under the Enterprise plan, about €20,000 a year |
   | Returns | Breach name, date, kinds of data. Never passwords | Full leaked records |
   | Already integrated | Yes | No |

   These terms were read from the suppliers' public pages in September 2026 and have not been confirmed with either supplier. The draft above names no supplier and requires written permission before purchase, which leaves the choice open. If you have a reason to prefer IntelX, such as better coverage of the malware logs that matter to crypto teams, name it and budget for the plan that permits this use.

3. **People mapping.** The original scope included finding founders, employees and contractors through public professional profiles. The prototype does not do this. Collecting profiles from LinkedIn breaches its terms, and the company that fought LinkedIn in court over it ended with a $500,000 judgment against it. The draft takes staff lists from the project itself. If mapping people from public sources matters to you, it needs a lawful source and legal advice first.

4. **Number of fixes in milestone 3.** This criterion is new. It shows that projects acted on what they were told, which is a stronger sign of value than reports delivered. Thirty is a guess. Set it after the first few pilots, or remove the criterion.

### What else changed from the original

- Milestone amounts: $35,000 / $35,000 / $60,000 / $20,000 became $30,000 / $30,000 / $75,000 / $15,000.
- "Weekly" updates became "scheduled" updates. The service scans daily, every three days or weekly, as the project chooses.
- Hard requirement 5, safe scanning, is new. The original had no equivalent.
- Hard requirement 1 now includes proof by DNS record, re-checked before every scan, in addition to manual approval.
- Milestone 2 now requires that no outside organisation is onboarded before the security assessment is published.
- The list of candidate inputs became a table of tools that are integrated.

### Before submitting

- Fill every **[DECIDE]**.
- Check that the test count and the number of checks still match the repository.
- The sample report shows a fresh domain. After fixing its findings, publish the second report, which shows them resolved.
- The other files in this directory hold longer versions of each section, and the reasoning behind the figures. `README.md` lists the remaining blanks.
- The fund changed its form after the first submission. Paste this into the current form at https://initiatives.thedao.fund/ and check that the sections still match.
