> Draft for review and editing. Not yet submitted.

# Adoption plan

The adoption milestone is half of the grant: $75,000 of $150,000. It passes when:

- at least 25 external Ethereum organisations have verified a domain and received at least 4 scheduled reports since the security assessment report was published,
- at least 10 of those organisations each secure over $1 million onchain in a Safe or in contracts on Ethereum or an L2, and
- those organisations have fixed at least 30 findings, each shown by a later scan that no longer reports it.

The technical reviewer counts all three. That is $3,000 for each organisation, and $7,500 for each of the 10 over the $1 million bar.

The exact wording is in `SUBMISSION.md`. The reasoning behind the numbers is in `05-milestones-budget.md`. A public adoption page, with the verified count and the reviewer's attestation, is a commitment in the submission and is not a payment criterion. An integration with another tool or body is an aim alongside the milestone, and is not a payment criterion either.

This file describes how to get there and how a reviewer can check it.

## State today

No organisation outside the team relies on the software. The web service has been live in beta at https://perimeterwatch.org since 30 September 2026, with sign-up open, and monitors only the maintainer's own domains. **[TODO: name any organisation that has agreed to pilot it.]**

## Timetable

| Months | Work | Adoption activity |
|---|---|---|
| 1 to 2 | Milestone 1: backups, monitoring, the missing parts of the onboarding flow, version 1.0 | Build the list of organisations to approach. Invite them into the open beta, telling each one that the service has had no independent review. Collect written intentions from those that prefer to wait for the review. Prepare onboarding material. Organisations that wish to can run the command-line tool themselves. |
| 3 | Milestone 2: independent security assessment and retest, breach data source, legal review | Outreach and onboarding continue. Nobody counts toward adoption until the assessment report is published. |
| 4 to 5 | Milestone 3: onboarding, monitoring and fixes | Bring on the organisations that waited for the review. Each organisation needs at least 4 scheduled reports after the day the report is published. Support organisations in making fixes. Publish the adoption page. |
| 6 | Milestone 4: end-of-phase report, maintenance plan | Monitoring continues. |

The months are this file's working plan. The submission states only the total of 6 months, and the fund fixes the timeline in the grant agreement.

Outreach and onboarding run from month 1, because the beta is open. What waits for the assessment report, at about the end of month 3, is the counting: an organisation counts once it has received at least 4 scheduled reports after the report is published. An organisation on the weekly schedule needs four weeks for that. The plan has adoption at about the end of month 5.

The target is still ambitious for one person and a funded developer. Ten of the 25 must be organisations that secure over $1 million onchain. Those take longer to bring on than a team of five, and they are the most likely to wait for the review before they join. For this reason the list of organisations to approach is longer than 25, and written intentions are collected from those that wait.

## How many to approach

Not every organisation that is approached will agree, and not every one that agrees will stay long enough to count. There is no data from this project on either rate. The planning assumption below is a guess and is marked as one.

| Stage | Number, for a target of 25 | Assumption |
|---|---|---|
| Approached | 125 | |
| Join the beta, or give a written intention to join after the review | 50 | 4 in 10 agree |
| Verified on the hosted service | 38 | 3 in 4 of those follow through |
| Received at least 4 scheduled reports since the assessment report was published | 25 or more | 2 in 3 of those stay |

The table counts organisations of any size. At least 10 of the 25 must each secure over $1 million onchain. With the same guessed rates, that means approaching about 50 organisations of that size, as part of the 125. They are reached mainly through referrals from security firms that already work with them.

**[TODO: replace these assumptions with real numbers after the first ten approaches.]**

## Candidate channels

No channel below has been approached. Each is a place where the intended users can be reached. **[TODO: for each, name the person you would contact and mark whether you already know them.]**

| Channel | Why it fits | First step | Contact |
|---|---|---|---|
| Other Round Two initiative teams | They are in the same programme and already care about security. | Offer them the pilot. | **[TODO]** |
| TheDAO Security Fund and Giveth networks | The fund wants its initiatives adopted. | Ask Griff for introductions to five projects. | Griff Green |
| SEAL | Organisations preparing for a SEAL certification need evidence for the DNS and identity modules. | Ask whether SEAL would mention the tool to organisations in preparation. | **[TODO]** |
| SEAL-accredited assessors and OpSec auditing firms | They meet organisations at the moment those organisations are paying attention to security. A firm can use the reports in its own assessments, which also counts as an integration. | Approach two or three firms with the sample report. | **[TODO]** |
| Layer 2 and ecosystem foundations | One agreement reaches many projects. | Offer the service to projects in their grant programmes. | **[TODO]** |
| Safe ecosystem | The signer check is specific to Safe. | Ask whether the tool could be listed among community tools. | **[TODO]** |
| Hackathons and accelerators | New teams set up their domain, email and GitHub organisation at this point. Problems fixed now do not accumulate. | Offer a short session and a free scan to each cohort. | **[TODO]** |
| Security conferences and community calls in the Ethereum ecosystem | Reaches the people who are asked by others what to use. | One talk or demonstration. | **[TODO: name the events in the grant period that you can attend.]** |
| Direct approach | Small teams answer a short personal message. | Use the message in `07-cofunding.md`. | **[TODO]** |

## What is never done to win users

- No organisation is scanned in order to show it its own weaknesses uninvited.
- No finding about any organisation is published or used in outreach.
- No list of organisations that declined is kept in public.

These follow from the opt-in principle. Breaking them would damage the project more than a missed milestone.

## Onboarding steps

Steps 1 to 5, 7 and 8 exist in the web service, which is live in beta. Nobody outside the team has followed them yet. Steps 9 and 10 are done by people.

| Step | Who | Time |
|---|---|---|
| 1. A contact person creates an account. | Organisation | 5 minutes |
| 2. They enter the domain, and optionally the GitHub organisation name and the addresses of their Safe and contracts. An organisation that is to count toward the $1 million bar gives those addresses to the reviewer. | Organisation | 5 minutes |
| 3. They add the DNS record shown on screen to prove control of the domain. No scan of any depth runs before this. | Organisation, whoever manages DNS | 10 minutes, plus waiting for DNS |
| 4. The first scan runs. | Service | Minutes |
| 5. They choose the depth of scan: passive only, probe, or active. | Organisation | 2 minutes |
| 6. Optionally they supply a list of staff email addresses, so that breach findings can tell current staff from former staff and shared mailboxes. Uploading a list in the web service is not built and is part of Milestone 1. The service never collects staff identities from professional networking sites. If the own-key route for breach data is chosen, they also supply a key. Supplying a key for each organisation is not built. | Organisation | 10 minutes |
| 7. They choose how often scans run (daily, every 3 days, weekly, or on request only) and where alerts go (email, Slack, Discord or Telegram). | Organisation | 5 minutes |
| 8. Scheduled scans begin. Scheduled reports count toward adoption from the day the assessment report is published. | Service | |
| 9. A 30-minute call to read the first report together and agree which findings to fix first. | Both | 30 minutes |
| 10. A check-in at 30 days. | Both | 15 minutes |

Step 9 matters most. A report that nobody reads produces no fixes.

To leave, the organisation removes the domain in the service. Its scans, findings and verification record are deleted at once. Audit log entries remain. Removing the DNS record alone withdraws authorisation: active checks and per-person detail stop, and standing is withdrawn after three failed daily checks.

Today each account is its own organisation. Inviting colleagues is not built and is part of Milestone 1. Until then a team shares one sign-in address.

## How adoption is measured

| Measure | Definition | Counted by |
|---|---|---|
| Verified organisation | An organisation whose domain control has been proved and is still proved | The service, at each scan |
| Received at least 4 scheduled reports | At least 4 scheduled scans completed after the day the assessment report was published, with verification in force at each. A scan that a person started by hand does not count. | The technical reviewer, from the scan history |
| Secures over $1 million onchain | The balance of a Safe or of contracts the organisation controls on Ethereum or an L2, read from the chain at addresses the organisation gives | The technical reviewer, who keeps the addresses and the query. No figure is taken from an aggregator dashboard. |
| Documented fix | A finding reported in one scan and recorded as resolved in a later scan in which the relevant check ran to completion | The engine's scan comparison, which is built |
| Time to fix | Days between the scan that first reported a finding and the scan that recorded it as resolved | The service |
| Integration | As described in `05-milestones-budget.md`. Not a payment criterion. | Evidence from the other party |

The rule about checks running to completion is important for honest counting. The engine already applies it: if a check was skipped or failed, its earlier findings are carried forward as stale and are not counted as fixed.

## How adoption is evidenced to the reviewer

A reviewer should not have to take the team's word.

| Claim | Evidence | Can the reviewer check it independently? |
|---|---|---|
| Organisation X uses the service | The DNS record at `_perimeterwatch-verify.<domain>` | Yes, by a public DNS query |
| Organisation X is a real, independent Ethereum organisation | Written confirmation from a named contact person at X, whose authority to act for X a person has confirmed | Yes, by contacting them |
| X secures over $1 million onchain | The addresses of its Safe or contracts on Ethereum or an L2 | Yes, by reading the balances from the chain |
| X received at least 4 scheduled reports since the assessment report was published | Scan history for X, with dates | Partly. The history is kept by the service. The contact person can confirm. |
| X fixed finding Y | The scan comparison showing Y reported and later resolved | Yes for findings based on public records, such as email and DNS settings. The reviewer can query the present state. For other findings, the contact person can confirm. |

### Confidentiality

The reviewer sees the names of all counted organisations and the kind of each fix. The reviewer does not need to see the findings themselves, and organisations must agree before any finding is shown to the reviewer.

Organisations are asked whether they agree to be named publicly, and are named only with their explicit approval. The others are named to the reviewer only. Some organisations will not want to say in public that they use a security monitoring service, and that is a reasonable position.

**[TODO: prepare a one-page consent form for organisations, covering: being named to the reviewer, being named publicly (optional), and having the kinds of fix counted in the public report. Have the lawyer review it with the other documents in Milestone 2.]**

## The integration

An integration is an aim alongside the adoption milestone. The submitted milestones do not require one. Candidates, in order of how directly they follow from work already done:

1. **An assessor uses the reports as evidence.** A SEAL-accredited assessor or OpSec auditing firm accepts Perimeterwatch reports for the DNS and email controls in a real assessment. The JSON output and schema are built. What is needed is a firm willing to try it and a mapping from findings to controls, which is not built.
2. **A rating body consumes the JSON output.** This depends on the OPSEC Ratings Coalition being formed and choosing to do so. The timing is outside the team's control.
3. **Another tool imports the JSON output.** **[TODO: name a candidate tool if you have one in mind.]**

**[TODO: choose the primary candidate and start the conversation during Milestone 1. Integrations depend on another party's timetable, which is why none is a payment criterion.]**

## After the milestone

The adoption page, which is a commitment in the submission, and the end-of-phase report from Milestone 4 give totals: organisations, scans, findings by kind, fixes by kind and median time to fix. They name no findings for any organisation. These totals would be the first public figures on the outside-in exposure of small crypto organisations that have opted in, and they are useful to SEAL, to the ratings coalition and to the fund when it decides what to pay for next.

## Notes for the maintainer (delete before submitting)

- The funnel numbers are guesses. Say so if asked.
- An organisation that chooses "on request only" has no scheduled scans and would not count towards the 25. Say so during onboarding.
- The funnel for 25 organisations starts with about 125 approaches, spread over about five months. That is a large outreach effort for one person and a funded developer. Read it against the time you have, and ask the fund for a longer adoption window in the grant agreement if you need one.
