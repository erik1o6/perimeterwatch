> Draft for review and editing. Not yet submitted.

# Milestones and budget

## The three numbers that are the maintainer's to set

| Number | Meaning | Placeholder used in this file | Set by |
|---|---|---|---|
| Total | The ask in USD | $140,000 | **[TODO]** |
| N | Organisations verified and monitored for at least 60 consecutive days | 12 | **[TODO]** |
| M | Documented fixes made by those organisations | 20 | **[TODO]** |

Every figure in this file that depends on these is a worked example and not a recommendation of a final amount. The reasoning behind the placeholders is at the end of the file.

## What is already done, and is not being paid for

The grant does not pay for work that exists. The following is built and passes 543 automated tests on the development machine: the scanning engine with all its checks, the command-line tool, the web service with sign-in, separation of organisations, domain verification, a scan queue, scheduled scans, alerts and an audit log, and the worker that runs scans and deletes old data. Drafts of the legal documents are written.

None of it has left the development machine. The code is not published. The web service has never been deployed. The deployment files and the CI workflow have never been run. No independent person has reviewed any of it. No organisation uses it.

The milestones pay for closing that gap.

## Structure

| Milestone | Share | At $140,000 | Due | Paid |
|---|---|---|---|---|
| M1. Public release and first deployment | 25% | $35,000 | End of month 2 | In advance, to the extent the fund's rules allow |
| M2. Hardening | 25% | $35,000 | End of month 4 | On acceptance |
| M3. Adoption | 50% | $70,000 | End of month 8 | On acceptance |

The fund requires at least one third of the budget behind an adoption milestone. This proposal puts half there, as the reviewer of the first submission asked.

The fund's announcement says: "The first milestone can be paid up to 50% in advance so the team has funding to start." **[TODO: ask Griff whether this means half of the first milestone's amount, or that a first milestone worth up to half of the total can be paid in advance. At $140,000 the first reading gives $17,500 in advance and the second gives $35,000. The cash-flow section below assumes the first, which is the less favourable.]**

Each milestone is judged pass or fail by an independent technical reviewer named in the agreement, and paid within 14 days of acceptance. If a milestone passes its delivery date, the team has 21 days to complete it before the fund can reclaim unspent funds.

Proposed reviewer, if the fund asks the team to suggest one: **[TODO: a person or firm with no ties to you, or write "to be named by the fund".]**

## Milestone 1: public release and first deployment (25%)

**What exists before this milestone starts.** The engine, the command-line tool and the web service, as listed above.

**What this milestone adds.** The code is published and released as version 1.0. The tests run in public. The web service is deployed for the first time and shown to work outside the test suite. Three features that the service needs before outside organisations can use it are built. The open question about breach data is answered.

**Pass criteria.** The reviewer can check each one without help from the team.

| # | Criterion | How the reviewer checks it |
|---|---|---|
| 1.1 | The repository is public under the Apache-2.0 licence, with its history from the first commit onward. | Open the URL. |
| 1.2 | Version 1.0.0 is tagged and has release notes. | Look at the releases page. |
| 1.3 | The CI workflow runs on every change, in public. Both of its jobs pass on the tagged release: the checks and tests, and the tests against a Postgres database. The number of tests is no lower than 540. | Open the latest run. |
| 1.4 | The container image builds from the published files, and the service starts from the published deployment instructions. | The reviewer follows `docs/operations.md` on a machine of their own. |
| 1.5 | A person can install the command-line tool from the written instructions and complete a passive scan of a domain they own in under 30 minutes. | The reviewer does it. |
| 1.6 | A sample report from a scan of a domain the team owns is published, as HTML and as JSON. The JSON validates against the published schema. | Open the URLs. Validate the file. |
| 1.7 | The web service is reachable at a public address. The reviewer can sign in by emailed link, add a domain they own, place the DNS record, and see the domain marked as verified. | The reviewer does it. |
| 1.8 | On the deployed service, a scan is refused after the DNS record of a verified domain is removed, including a scan that was already waiting in the queue. | The reviewer tries both. |
| 1.9 | On the deployed service, a completed scan produces the same findings as the command-line tool run against the same domain on the same day at the same depth. | The reviewer compares the two JSON reports. |
| 1.10 | The address that scan traffic comes from is fixed and published. The worker cannot reach private address ranges or the cloud metadata address. | The reviewer reads the published address and the firewall rules, and sees a test from inside the worker fail to connect. |
| 1.11 | A backup of the database has been restored into an empty deployment and the findings in it can be read. | The reviewer sees the record of the restore. |
| 1.12 | An account holder can invite a colleague to their organisation, and remove them. The tests that try every route as another organisation cover the new routes. | The reviewer does it, and reads the test. |
| 1.13 | The database itself refuses to return one organisation's rows to a connection acting for another (row-level security). | The reviewer reads the migration and the test that attempts it. |
| 1.14 | A person can sign in with an Ethereum wallet as an alternative to the emailed link. | The reviewer does it. |
| 1.15 | A written answer from Have I Been Pwned is on file about use of its data by a hosted service, and the plan for breach data in the service follows that answer. | The reviewer reads the correspondence. |
| 1.16 | On the deployed service, a domain whose control has not been proved is never scanned. A request for a scan of any depth is refused, and no scan of it is ever scheduled. | The reviewer adds a domain without proving control, tries to start a scan at each depth, chooses a daily schedule, and sees after several days that the scan history is empty. |
| 1.17 | No organisation outside the team has been onboarded. Test domains belong to the team or the reviewer. | Statement by the team, and the reviewer inspects the list of verified domains. |

Criterion 1.17 exists because the service must not hold other organisations' data before the security review in Milestone 2.

## Milestone 2: hardening (25%)

**What exists before this milestone starts.** The deployed service from Milestone 1. Draft legal documents. Alerts and scheduled scans that work in tests.

**What this milestone adds.** An independent security firm reviews the service and the findings are fixed. A lawyer reviews the legal documents. Scheduled scans and alerts are shown running in the deployment for 30 days.

| # | Criterion | How the reviewer checks it |
|---|---|---|
| 2.1 | An independent firm has completed a security review of the deployed service. The scope covers at least: sign-in and sessions, separation between organisations' data, the authorisation check, encryption of stored findings, the scan workers, and the deployment. | The reviewer reads the report and the statement of scope. |
| 2.2 | Every finding the firm rated critical or high is fixed, and the firm has confirmed each fix in writing. Findings rated medium are fixed or have a written reason for acceptance. | The reviewer reads the retest letter. |
| 2.3 | A summary of the review is published. | Open the URL. |
| 2.4 | Terms of service, a privacy notice and a data processing agreement are published. A qualified lawyer has reviewed them, and the open questions listed in `docs/legal/README.md` each have a written answer. | Open the documents. The reviewer sees a letter or invoice from the lawyer naming the documents. |
| 2.5 | A written policy is published covering: what is kept and for how long, how an organisation deletes its data, how the service responds if it is itself breached, with named contacts, and how the operator of a host asks for scans of it to stop. | Open the URL. |
| 2.6 | Scheduled scans run without a person starting them. At least 30 consecutive days of scheduled scans are recorded in the deployment for the team's own test domains. | The reviewer inspects the scan history. |
| 2.7 | An alert is sent when a scan finds something new. The reviewer makes a change on a domain they control, for example removing a DMARC record, and receives an alert after the next scheduled scan. The alert contains no name, address or credential. | The reviewer does it. |
| 2.8 | Automatic deletion has run in the deployment: no scan older than the retention period remains, other than the latest scan of each domain. | The reviewer inspects the scan history and the audit log. |
| 2.9 | A request to stop scanning a host has been acted on in the deployment, using a host the reviewer names. After it, no scan contacts that host. | The reviewer names a host they control and watches its logs. |
| 2.10 | **[TODO: keep this only if you chose Option B in `04-team.md`.]** A second person has commit and deployment rights and has carried out one deployment. | The reviewer sees the deployment record. |

**A question for the fund.** The background notes for this proposal say the fund does not pay for audits. That statement was not found in the public Round Two announcement. **[TODO: ask Griff whether an independent security review of the hosted service can be paid from the grant. If not, the review is the most suitable item for a co-funder to pay for or for a security firm to donate. See `07-cofunding.md`.]** The review is kept as a pass criterion in either case, because the service should not hold other organisations' data without it.

## Milestone 3: adoption (50%)

**What exists before this milestone starts.** A deployed, reviewed service with no outside users.

**What this milestone adds.** Named organisations use the service in production, have fixed problems it found, and its output is used by at least one other tool or body.

| # | Criterion | How the reviewer checks it |
|---|---|---|
| 3.1 | N organisations have each proved control of their domain and been scanned on schedule for at least 60 consecutive days. | For each organisation, the reviewer queries the public DNS record at `_parapet-verify.<domain>` and inspects the scan history for that domain. |
| 3.2 | Each of the N organisations is a crypto project, and is independent of the team. No more than two of them share an owner or a founder. | The reviewer reads the list. |
| 3.3 | Each of the N organisations is named to the reviewer, and a contact person at each has confirmed in writing that the organisation uses the service. At least half agree to be named publicly. | The reviewer reads the confirmations and may contact any of them. |
| 3.4 | M fixes are documented across those organisations. A fix counts when a finding was reported in one scan and recorded as resolved in a later scan in which the relevant check ran to completion. | The reviewer inspects the scan comparison for each fix. For findings based on public records, such as a missing DMARC record, the reviewer can confirm the present state independently. |
| 3.5 | The M fixes come from at least half of the N organisations, and no single organisation accounts for more than a quarter of them. | The reviewer counts. |
| 3.6 | At least one integration is in production use. See the definition below. | The reviewer sees the integration working with real data from at least one consenting organisation. |
| 3.7 | A public report gives the totals: organisations, scans, findings by kind, fixes by kind, and median time from report to fix. It names no organisation that has not agreed to be named and gives no finding for any named organisation. | Open the URL. |

**What counts as an integration.** One of the following, in production and used by someone other than the team.

- An OpSec auditing firm or a SEAL-accredited assessor uses Parapet reports as evidence in a real assessment of a consenting organisation.
- A rating body, such as the group that forms under the OPSEC Ratings Coalition initiative, consumes the JSON output for a consenting organisation.
- Another security tool or dashboard imports the JSON output through a documented interface.
- A security firm runs its own copy of the open-source service for its clients.

Candidate integration partner: **[TODO: name one if a conversation has started. Otherwise write "to be identified during Milestone 1".]**

**What does not count towards N.** Domains owned by the team. Organisations that verified but were scanned for less than 60 consecutive days. Organisations that only ran the command-line tool themselves, unless they confirm in writing and share the scan history with the reviewer.

## Worked budget at the placeholder total of $140,000

All amounts are placeholders unless marked as a published price.

| Item | Basis | Amount |
|---|---|---|
| Maintainer: release, deployment, operations, fixes from the review, onboarding support | 8 months at $11,000 per month **[TODO: your rate and hours]** | $88,000 |
| Second contributor, part-time | **[TODO: rate and scope]** | $10,000 |
| Independent security review, including retest | **[TODO: obtain two quotes]** | $20,000 |
| Legal review of the draft documents, and advice on the entity | **[TODO: obtain a quote]** | $6,000 |
| Hosting, 8 months | $300 per month **[TODO: size this after the first deployment]** | $2,400 |
| Breach data subscription, 8 months | Have I Been Pwned Pro 1 at $379 per month (published price) | $3,032 |
| Adoption work: onboarding calls, documentation, attendance at one event | **[TODO]** | $8,000 |
| Contingency | | $2,568 |
| **Total** | | **$140,000** |

### When money arrives and when it is spent

This table shows a gap that the maintainer should plan for. It assumes the less favourable reading of the prepayment rule.

| Point in time | Received so far | Spent so far (estimate) |
|---|---|---|
| Start | $17,500 (half of M1 in advance) | $0 |
| M1 accepted, month 2 | $35,000 | About $26,000 |
| M2 accepted, month 4 | $70,000 | About $78,000, because the security review and the legal review fall here |
| M3 accepted, month 8 | $140,000 | About $140,000 |

Half of the grant arrives only after the adoption milestone passes. Between month 4 and month 8 the project spends more than it has received. **[TODO: state how this gap is covered. Options: you defer part of your own pay until M3, a co-funder pays the security review directly, or the entity has other funds.]**

If Milestone 3 fails, the project has received half of the total and spent more than that. This is the intended effect of a 50% adoption milestone, and the maintainer should accept it knowingly.

## Recurring costs after the grant

The service costs money every year it runs. The grant covers the first 8 months only.

| Item | Yearly cost | Note |
|---|---|---|
| Hosting | About $3,600 | Placeholder. Grows with the number of organisations. |
| Breach data subscription | $4,548 for Have I Been Pwned Pro 1, covering up to 50 domains. $8,388 for Pro 2, covering up to 100. | Published prices, checked 29 September 2026. May be unnecessary if each organisation brings its own key. See `08-risks.md`. |
| Security review | About $10,000 to $20,000 | Placeholder. A service that holds this data should be reviewed every year and after major changes. |
| Maintenance and support | **[TODO: hours per week at your rate]** | The largest cost. |
| Legal and administration for the entity | **[TODO]** | |

Source for the subscription prices: https://haveibeenpwned.com/Subscription

**No paid subscription is taken out before funding arrives.** Until then the breach check stays switched off: it needs a paid key. Every other check works without one. The subscription is bought in Milestone 1, once the fund has paid and Have I Been Pwned has answered in writing.

**How these are paid after the grant.** **[TODO: choose and describe. Options, which can be combined:**
- **Free for every organisation, paid for by yearly contributions from larger ecosystem organisations.**
- **Free for small teams, with a fee for organisations above a size threshold.**
- **Free to self-host always, with a fee for the hosted service.**
- **A follow-on grant. If this is the only plan, say so plainly.]**

## Reasoning behind the placeholder values

**Total: $140,000.** Round Two initiatives range from $20,000 to $600,000, and most sit between $120,000 and $300,000. The OPSEC Ratings Coalition is $150,000 and the Auditware EDR grant is $300,000. This project has one maintainer and software that is already built, so less engineering remains than in most proposals. What remains is mostly work that cannot be done alone at a desk: deployment and operation, an outside review, legal review, and adoption. A figure in the lower part of the range fits that. Going much lower would leave no room for the security review. The fund's own test applies here: the announcement says that if beneficiaries will not contribute, "either it's the wrong solution or they don't think it's urgent or maybe they are asking for too much money".

**N: 12.** Onboarding can only start after Milestone 2 is accepted, at about month 4. Each organisation then needs 60 consecutive days of monitoring before month 8. That leaves roughly two months in which to bring organisations on. The assumption is that one maintainer can onboard and support one or two organisations a week alongside other work. On that assumption twelve is reachable with some margin. A number such as 30 would look better and would put half of the grant at risk. **[TODO: if you already have organisations waiting, raise N. If you have none, consider 10.]**

**M: 20.** This is fewer than two fixes per organisation. Some findings are quick to fix, such as publishing a DMARC record or a CAA record. There is no data yet on how many findings a typical crypto organisation has or how many it will fix, because no outside organisation has used the tool. **[TODO: after the first two or three pilot scans, revise M using what you observe.]**

**Integrations: 1.** An integration depends on another party's timetable. One is a commitment that can be kept. More than one can be reported as a bonus.

**Duration: 8 months.** Two months to publish, deploy and finish the three remaining features. Two for review and hardening. Four for onboarding and the 60-day monitoring period.

## Notes for the maintainer (delete before submitting)

- Milestone 1 is a quarter of the total and the software it builds on already exists. A reviewer may ask whether 25% is too much for it. The answer in this file is that M1 pays for the first real deployment, three features, and the operational work around them. If you think that answer is weak, the honest alternatives are to lower the total, or to move the security review into M1 and the 30 days of operation into M2. The split itself stays at 25, 25 and 50.
- Criterion 1.14 (wallet sign-in) is included because it is on the list of things not yet built. It is the item in M1 that organisations need least. Remove it if you do not want to be held to it.
- Criterion 1.16 checks behaviour that is already built and tested (class `TestOptIn` in `tests/web/test_flows.py`). The milestone adds the proof that it holds in a real deployment. It depends on the setting `PARAPET_SCAN_REQUIRES_VERIFICATION`, which is on by default and must stay on in the deployment.
- The budget items are not tied to milestones one for one, because the payment schedule and the spending schedule differ.
- If you change N or M, change them in `09-adoption-plan.md` as well. If you change the total, change it in `07-cofunding.md` as well.
