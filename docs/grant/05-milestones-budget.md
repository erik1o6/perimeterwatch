> Draft for review and editing. Not yet submitted.

# Milestones and budget

The milestones that go into the fund's form are in `SUBMISSION.md` and `10-resubmission.md`. This file gives the longer working version: what each milestone builds on, the checks behind each submitted criterion, and a worked budget. Where the two differ, the submission governs.

## The numbers, as submitted

| Number | Meaning | Value |
|---|---|---|
| Total | The ask in USD | $150,000 |
| Duration | Months from funding to the last milestone | 6 |
| Organisations | External Ethereum organisations that have verified a domain and received at least 4 scheduled reports since the assessment report was published | At least 25 |
| Value bar | Organisations among them that each secure over $1 million onchain in a Safe or in contracts on Ethereum or an L2 | At least 10 |
| Fixes | Findings fixed by those organisations, each shown by a later scan that no longer reports it | At least 30 |

The reasoning behind each value is at the end of the file.

## What is already done, and is not being paid for

The grant does not pay for work that exists. The following is built and passes 2,560 automated tests in public CI: the scanning engine with its 34 checks, the command-line tool, the web service with sign-in, separation of organisations, domain verification, a scan queue, scheduled scans, alerts and an audit log, and the worker that runs scans and deletes old data. Drafts of the legal documents are written and published at https://perimeterwatch.org/legal, marked as drafts.

The code is published at https://github.com/erik1o6/perimeterwatch. The web service has been live in beta at https://perimeterwatch.org since 30 September 2026, on one server in Germany, with sign-up open. Only the maintainer's own domains are monitored. The CI workflow runs in public on every change and passes: tests on Python 3.13 and 3.14, tests against Postgres, a dependency audit and a build of the container image. No independent person has reviewed any of it. No lawyer has reviewed the legal drafts. No outside organisation relies on it. There is no paid data subscription, so the breach check is built and switched off.

The milestones pay for closing that gap.

## Structure

| Milestone | Share | Amount | Working target | Paid |
|---|---|---|---|---|
| M1. Hardened service | 20% | $30,000 | End of month 2 | Up to 50% in advance, under the fund's rules. The rest on acceptance |
| M2. Security assessment, breach monitoring and legal review | 20% | $30,000 | End of month 3 | On acceptance |
| M3. Verified adoption | 50% | $75,000 | End of month 5 | On acceptance |
| M4. Continued operation and maintenance | 10% | $15,000 | End of month 6 | On acceptance |
| **Total** | **100%** | **$150,000** | | |

The fund requires at least one third of the budget behind an adoption milestone. This proposal puts half there, as the reviewer of the first submission asked.

The working targets are this file's plan. The submission states only the total duration of 6 months. The fund fixes the timeline in the grant agreement.

The fund's rules say: "The first milestone can be paid up to 50% in advance so the team has funding to start." **[TODO: ask the fund whether this means half of the first milestone's amount, or that a first milestone worth up to half of the total can be paid in advance. At $150,000 the first reading gives $15,000 in advance and the second gives $30,000. The cash-flow section below assumes the first, which is the less favourable.]**

Each milestone is judged pass or fail by an independent technical reviewer named in the grant agreement, and paid within 14 days of acceptance.

Proposed reviewer, if the fund asks the team to suggest one: **[TODO: a person or firm with no ties to you, or write "to be named by the fund".]**

## Milestone 1: hardened service ($30,000)

**What exists before this milestone starts.** The engine, the command-line tool and the web service in beta, as listed above.

**What this milestone adds.** A beta deployment already exists, so this milestone does not pay for a first deployment. It pays for making the service fit for other organisations: backups with a tested restore, monitoring, the parts of the onboarding flow that are missing, and a tagged 1.0 release. The independent security assessment is in Milestone 2, because the assessor's bill of about $20,000 cannot be paid before the first payment arrives.

**Submitted criteria.**

- Version 1.0 is tagged in the public repository with colleague invitations, staff list upload and account closure.
- A public test report shows a backup restored into an empty deployment and a monitoring alert delivered, confirmed by the technical reviewer.

**Working checks behind them.** The reviewer can check each one without help from the team.

| # | Check | How the reviewer checks it |
|---|---|---|
| 1.1 | Version 1.0.0 is tagged and has release notes that separate funded work from work done before the grant. | Look at the releases page. |
| 1.2 | An account holder can invite a colleague to their organisation and remove them, upload a staff list, and close the account. The tests that try every route as another organisation cover the new routes. | The reviewer does it, and reads the tests. |
| 1.3 | A backup of the database has been restored into an empty deployment and the findings in it can be read. | The reviewer reads the public test report and sees the record of the restore. |
| 1.4 | Monitoring of the service is in place, and a test alert has been delivered to the maintainers. | The reviewer reads the public test report. |

**Working checks that are not payment criteria.**

| # | Check | How the reviewer checks it |
|---|---|---|
| 1.5 | The CI workflow passes on the tagged release: the checks and tests, and the tests against a Postgres database. The number of tests is no lower than 2,500. | Open the latest run. |
| 1.6 | The container image builds from the published files, and the service starts from the published deployment instructions. | The reviewer follows `docs/operations.md` on a machine of their own. |
| 1.7 | On the deployed service, a domain whose control has not been proved is never scanned. A request for a scan of any depth is refused, no scan of it is ever scheduled, and a scan is refused after the DNS record of a verified domain is removed, including a scan that was already waiting in the queue. | The reviewer adds a domain without proving control and tries each depth, then removes the record of a verified domain and tries again. |
| 1.8 | One organisation cannot read or change another's data. | The reviewer reads the tests that try every route as another organisation. |
| 1.9 | The addresses that scan traffic comes from are fixed and published. The worker cannot reach private address ranges or the cloud metadata address. | The reviewer reads the published addresses and the firewall rules, and sees a test from inside the worker fail to connect. |

Already met before the grant, and listed so that a reviewer can see it: the repository is public under Apache-2.0 with its history, a sample report is published at https://perimeterwatch.org/sample-report, the service is reachable at a public address, and the scan addresses are shown on its home page.

Planned hardening that is not a payment criterion: a second barrier in the database, so that the database itself refuses to return one organisation's rows to a connection acting for another (row-level security). Sign-in with a wallet is not part of the submitted milestones.

## Milestone 2: security assessment, breach monitoring and legal review ($30,000)

**What exists before this milestone starts.** The hardened service from Milestone 1. Draft legal documents. A breach check that is built and switched off. Scheduled scans and alerts that run in the beta for the maintainer's own domains.

**What this milestone adds.** An independent security assessment with its fixes and a retest. A licensed source of breach data in production. A lawyer's review of the legal documents.

The beta is open and states that it has had no independent review. Organisations may join it, and none counts toward adoption until the assessment and retest report is published.

The planned breach data source is Have I Been Pwned. Intelligence X, which the first submission named, is the alternative. The choice is made once a supplier confirms in writing that a hosted service may use the data for several organisations. No subscription is bought before that.

**Submitted criteria.**

- An independent security assessment and retest report is published, with every critical and high finding confirmed fixed by the assessor.
- The licensed breach source runs in production, and the technical reviewer has seen the supplier's written permission to serve several organisations.
- The terms of service, privacy policy and data processing agreement are published as reviewed by a lawyer, and the technical reviewer has seen the lawyer's letter.

**Working checks behind them.**

| # | Check | How the reviewer checks it |
|---|---|---|
| 2.1 | An independent firm has completed a security assessment of the deployed service. The scope covers at least: sign-in and sessions, separation between organisations' data, the authorisation check, encryption of stored findings, the scan workers, and the deployment. | The reviewer reads the report and the statement of scope. |
| 2.2 | Every finding the firm rated critical or high is fixed, and the firm has confirmed each fix in writing. Findings rated medium are fixed or have a written reason for acceptance. | The reviewer reads the retest report. |
| 2.3 | The assessment and retest report is published, without participant information or sensitive exploit details. | Open the URL. |
| 2.4 | The supplier's written permission to serve several organisations is on file, and the breach check in the service follows it. | The reviewer reads the correspondence. |
| 2.5 | Terms of service, a privacy policy and a data processing agreement are published. A lawyer has reviewed them, and the open questions listed in `docs/legal/README.md` each have a written answer. | Open the documents. The reviewer sees the lawyer's letter naming the documents. |

**Working checks that are not payment criteria.**

| # | Check | How the reviewer checks it |
|---|---|---|
| 2.6 | A written policy is published covering: what is kept and for how long, how an organisation deletes its data, how the service responds if it is itself breached, with named contacts, and how the operator of a host asks for scans of it to stop. | Open the URL. |
| 2.7 | Scheduled scans run without a person starting them. At least 30 consecutive days of scheduled scans are recorded in the deployment for the team's own test domains. | The reviewer inspects the scan history. |
| 2.8 | An alert is sent when a scan finds something new. The reviewer makes a change on a domain they control, for example removing a DMARC record, and receives an alert after the next scheduled scan. The alert contains no name, address or credential. | The reviewer does it. |
| 2.9 | The human-review workflow for high-risk or uncertain findings is documented and shown on a test record. | The reviewer reads the record. |
| 2.10 | Automatic deletion has run in the deployment: no scan older than the retention period remains, other than the latest scan of each domain. | The reviewer inspects the scan history and the audit log. |
| 2.11 | A request to stop scanning a host has been acted on in the deployment, using a host the reviewer names. After it, no scan contacts that host. | The reviewer names a host they control and watches its logs. |

**A question for the fund.** **[TODO: ask the fund whether an independent security review of the hosted service can be paid from the grant. If not, the review is the most suitable item for a security firm to give in kind or for a co-funder to pay for. See `07-cofunding.md`.]** The review stays a pass criterion in either case, because no organisation should count toward adoption without it.

## Milestone 3: verified adoption ($75,000, the adoption milestone)

**What exists before this milestone starts.** A deployed, reviewed service. The assessment report is published.

**What this milestone adds.** At least 25 outside organisations use the service in production, at least 10 of them securing over $1 million onchain, and they have fixed problems it found.

**Submitted criteria.**

- At least 25 external Ethereum organisations have verified a domain and received at least 4 scheduled reports since the assessment report was published, counted by the technical reviewer from production records under confidentiality.
- At least 10 of those organisations each secure over $1 million onchain in a Safe or in contracts on Ethereum or an L2, measured by the technical reviewer from onchain balances.
- At least 30 findings have been fixed by those organisations, each shown by a later scan that no longer reports it, counted by the technical reviewer.

**Working checks behind them.**

| # | Check | How the reviewer checks it |
|---|---|---|
| 3.1 | Each counted organisation has proved control of its domain and received at least 4 scheduled reports after the date the assessment report was published. | For each organisation, the reviewer queries the public DNS record at `_perimeterwatch-verify.<domain>` and inspects the scan history for that domain. |
| 3.2 | Each counted organisation is independent of the team, and a person has confirmed that the requester has authority to act for it. | The reviewer reads the list and the record of each confirmation. |
| 3.3 | At least 10 of the counted organisations each secure over $1 million in a Safe or in contracts on Ethereum or an L2. | The organisation gives the addresses. The reviewer reads the balances from the chain and keeps the addresses and the query. No figure is taken from an aggregator dashboard. |
| 3.4 | A fix counts when a finding was reported in one scan and recorded as resolved in a later scan in which the relevant check ran to completion. | The reviewer inspects the scan comparison for each fix. For findings based on public records, such as a missing DMARC record, the reviewer can confirm the present state independently. |

**What does not count.** Domains owned by the team. Demonstrations and internal pilots. Organisations with fewer than 4 scheduled reports since the assessment report was published. Organisations that only ran the command-line tool themselves.

**The adoption page is a commitment, not a payment criterion.** A public page gives the verified count and the reviewer's attestation. An organisation is named only with its approval, and no findings are shown. It sits under "Commitments" in the submission, because the fund's guide does not count the proposer's own paperwork as adoption.

**Working aims that are not payment criteria.** The fixes come from at least half of the organisations, so that the figure does not rest on one or two of them. One integration is in use by someone other than the team: an OpSec auditing firm or a SEAL-accredited assessor using the reports as evidence, a rating body reading the JSON output for a consenting organisation, or another tool importing the JSON output. Candidate integration partner: **[TODO: name one if a conversation has started.]**

## Milestone 4: continued operation and maintenance ($15,000)

**What this milestone adds.** Six months of monitoring delivered, and the documents that say how the service carries on.

**Submitted criteria.**

- A public end-of-phase report covers six months of monitoring, source coverage and limitations, with no participant identities or findings.
- A published maintenance plan names the maintainers, the recurring costs and the funding needed after the grant.

The fee for larger organisations is a commitment in the submission and is not a criterion here: the fee and its trigger are published before any charge.

## Worked budget at $150,000

Every amount is a planning estimate, not a signed supplier quote, unless it is marked as a published price.

| Item | Basis | Amount |
|---|---|---|
| Maintainer (code2142): hardening, review fixes, operations, onboarding, review of findings | 6 months at $11,000 per month. Estimate. **[TODO: your rate and hours]** | $66,000 |
| Developer and part-time operations support | Estimate. **[TODO: rate and scope]** | $30,000 |
| Independent security assessment, including retest | Estimate, not a quote. **[TODO: obtain two quotes]** | $20,000 |
| Legal review of the draft documents, and advice on the entity | Estimate, not a quote. **[TODO: obtain a quote]** | $6,000 |
| Setting up and administering the non-profit | Estimate. **[TODO: depends on legal form and jurisdiction]** | $5,000 |
| Breach data licence, one full year | Have I Been Pwned Pro 1 at $379 per month (published price, checked 30 September 2026). The Intelligence X alternative costs more: see the note below | $4,548 |
| Hosting, 6 months | $300 per month. Estimate with room to grow: the beta server costs far less today | $1,800 |
| Adoption work: onboarding calls, documentation, attendance at one event | Estimate. **[TODO]** | $8,000 |
| Independent technical reviewer's fee | Estimate. The fund's rules take it out of the milestone payments unless the reviewer works pro bono | $4,000 |
| Contingency |  | $4,652 |
| **Total** | | **$150,000** |

The breach data line uses the published price of the planned source. Intelligence X, the alternative, costs more. Its Identity Portal plan costs about $11,400 a year and its Enterprise plan about $22,700 a year. Both are converted from the supplier's published euro prices, read on 30 September 2026, at the European Central Bank's reference rate of that day (1.1355). Which plan allows service to several organisations has not been confirmed with the supplier. Choosing Intelligence X would take money from contingency and from the developer line.

If a security firm gives the assessment in kind, the $20,000 line is freed. **[TODO: say where it goes.]**

### When money arrives and when it is spent

This table shows a gap that the maintainer should plan for. It assumes the less favourable reading of the prepayment rule, spreads the cost of people evenly over the six months, and uses the estimates above.

| Point in time | Received so far | Spent so far (estimate) |
|---|---|---|
| Start | $15,000 (half of M1 in advance) | $0 |
| M1 accepted, end of month 2 | $30,000 | About $39,000 |
| M2 accepted, end of month 3 | $60,000 | About $89,000, because the security assessment, the legal review and the data licence fall here |
| M3 accepted, end of month 5 | $135,000 | About $128,000 |
| M4 accepted, end of month 6 | $150,000 | About $150,000 |

With the assessment in Milestone 2, its bill falls after the first milestone has been paid in full. Half of the grant still arrives only after the adoption milestone passes. Until then the project has received $60,000 and spent about $128,000. **[TODO: state how this gap is covered. Options: you defer part of your own pay until M3, a security firm gives the assessment in kind, a co-funder pays a bill directly, or the entity has other funds. The fund's rules say a team that needs more mid-milestone is expected to seek a stop-gap loan from the ecosystem.]**

If Milestone 3 fails, the project has received $60,000 and spent more than that. This is the intended effect of a 50% adoption milestone, and the maintainer should accept it knowingly.

## Recurring costs after the grant

The service costs money every year it runs. The grant covers the first 6 months of operation and one full year of the breach data licence.

| Item | Yearly cost | Note |
|---|---|---|
| Hosting | About $3,600 | Estimate. Grows with the number of organisations. |
| Breach data subscription | $4,548 for Have I Been Pwned Pro 1, covering up to 50 domains. $8,388 for Pro 2, covering up to 100. | Published prices, checked 30 September 2026. May be unnecessary if each organisation brings its own key. See `08-risks.md`. |
| Security review | About $10,000 to $20,000 | Estimate. A service that stores this data should be reviewed every year and after major changes. |
| Maintenance and support | **[TODO: hours per week at your rate]** | The largest cost. |
| Legal and administration for the entity | **[TODO]** | |

Source for the subscription prices: https://haveibeenpwned.com/Subscription

**No paid subscription is taken out before funding arrives.** Until then the breach check stays switched off: it needs a paid key. Every other check works without one. The subscription is bought in Milestone 2, once the fund has paid and the supplier has answered in writing.

**How these are paid after the grant.** The submission states the plan. Operation after month 6 depends on further funding: sponsorships, donations and grants first. If those fall short, organisations with more than 20 people get a free month, keep their report, and pay for monitoring after that. The fee and its trigger are published before any charge. No funding after month 6 is confirmed today.

## Reasoning behind the values

**Total: $150,000.** The 43 initiatives on the fund's board on 30 September 2026 range from $10,000 to $640,000. The OPSEC Ratings Coalition is $150,000 and the Auditware EDR grant is $300,000. This project has one maintainer and software that is already built and running, so less engineering remains than in most proposals. What remains is mostly work that cannot be done alone at a desk: an outside review, legal review, operation, and adoption. The fund's own test applies here: its Round Two announcement says that if beneficiaries will not contribute, "either it's the wrong solution or they don't think it's urgent or maybe they are asking for too much money".

**What the fund pays per organisation.** The adoption milestone pays $75,000 for at least 25 organisations, which is $3,000 each, and $7,500 for each of the 10 that secure over $1 million onchain. The whole grant is $150,000, which is $6,000 for each of the 25. The fund's drafting guide says its admin works out both figures for every submission.

**Organisations: 25.** This is the number in the first submission. Outreach and onboarding into the open beta run from month 1, and each organisation is told that the service has had no independent review. An organisation counts once it has received at least 4 scheduled reports after the assessment report is published, at about the end of month 3 in the working plan. Adoption is planned for about the end of month 5, which gives about five months of onboarding. One maintainer can onboard and support one or two organisations a week alongside other work. The target is still ambitious for one person and a funded developer. Some organisations will wait for the review before they join, and the larger ones are the most likely to wait. This is a real risk and half of the grant rests on it. The fund fixes the timeline in the grant agreement, and its guide says an adoption target can take the time it needs. See `08-risks.md` and `09-adoption-plan.md`.

**Value bar: 10 organisations securing over $1 million each.** The fund's guide says a count of adopters needs a value bar or a named list, so that the adopters are ones whose safety matters. The bar qualifies the adopting organisation: a Safe or contracts it controls on Ethereum or an L2, measured from onchain balances. The other 15 can be smaller teams, which are the ones the service is built for.

**Fixes: 30.** This is a little more than one fix per organisation. Some findings are quick to fix, such as publishing a DMARC record or a CAA record. There is no data yet on how many findings a typical crypto organisation has or how many it will fix, because no outside organisation has used the service. The figure is a judgement, not a measurement.

**Scheduled reports: 4 per organisation.** The service scans daily, every three days or weekly, as the organisation chooses. Four scheduled reports take between four days and four weeks.

**Duration: 6 months.** Two months for the hardening work and the 1.0 release. One for the security assessment and its fixes, the breach data source and the legal review. Two more for the scheduled reports that count and for fixes. One for the close-out. Outreach and onboarding run alongside from month 1. The assessment can be commissioned during the first two months, so that its report lands in the third, if the firm agrees to be paid after Milestone 1 is accepted.

## Notes for the maintainer (delete before submitting)

- The security assessment sits in Milestone 2, by the maintainer's decision of 30 September 2026: a firm's bill of about $20,000 cannot be paid before the first payment arrives. The cost is that organisations start to count a month later than they would with the assessment in Milestone 1. Onboarding into the open beta does not wait for it.
- The budget items are not tied to milestones one for one, because the payment schedule and the spending schedule differ.
- The check that no unverified domain is scanned tests behaviour that is already built (class `TestOptIn` in `tests/web/test_flows.py`). It depends on the setting `PW_SCAN_REQUIRES_VERIFICATION`, which is on by default and must stay on in the deployment.
- If you change the number of organisations, the value bar or the number of fixes, change them in `SUBMISSION.md`, `10-resubmission.md`, `01-summary.md`, `07-cofunding.md`, `08-risks.md` and `09-adoption-plan.md` as well. If you change the total, change it in the same files.
