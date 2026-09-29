> Draft for review and editing. Not yet submitted.

# Adoption plan

The adoption milestone is half of the grant. It passes when:

- N organisations have proved control of their domain and been monitored for at least 60 consecutive days,
- those organisations have made M documented fixes, and
- at least one integration is in production use.

Placeholder values: N = 12, M = 20. **[TODO: set both. The reasoning is in `05-milestones-budget.md`.]**

This file describes how to get there and how a reviewer can check it.

## State today

No organisation outside the team uses the software. The web service is built and has never been deployed. **[TODO: correct this if it is wrong, and name any organisation that has run the tool or agreed to pilot it.]**

## Timetable

| Months | Work | Adoption activity |
|---|---|---|
| 1 to 2 | Milestone 1: public release and first deployment | Publish the repository and sample report. Collect written intentions to pilot. Organisations that wish to can run the command-line tool themselves. |
| 3 to 4 | Milestone 2: security review, legal review, 30 days of operation | Confirm the pilot list. Prepare onboarding material. No outside organisation is onboarded to the hosted service yet. |
| 5 to 6 | Onboarding | Onboard organisations in small groups. The 60-day period starts for each on the day of its first scheduled scan after verification. |
| 7 to 8 | Monitoring and fixes | Support organisations in making fixes. Complete the integration. Write the public report. |

The timetable is tight at one point. An organisation onboarded after the end of month 6 cannot complete 60 days by the end of month 8. For this reason the target for written intentions is higher than N.

## How many to approach

Not every organisation that is approached will agree, and not every one that agrees will stay for 60 days. There is no data from this project on either rate. The planning assumption below is a guess and is marked as one.

| Stage | Number, for N = 12 | Assumption |
|---|---|---|
| Approached | 60 | |
| Written intention to pilot | 24 | 4 in 10 agree |
| Verified on the hosted service | 18 | 3 in 4 of those follow through |
| Monitored for 60 consecutive days | 12 or more | 2 in 3 of those stay |

**[TODO: replace these assumptions with real numbers after the first ten approaches.]**

## Candidate channels

No channel below has been approached. Each is a place where the intended users can be reached. **[TODO: for each, name the person you would contact and mark whether you already know them.]**

| Channel | Why it fits | First step | Contact |
|---|---|---|---|
| Other Round Two initiative teams | They are in the same programme and already care about security. | Offer them the pilot. | **[TODO]** |
| TheDAO Fund and Giveth networks | The fund wants its initiatives adopted. | Ask Griff for introductions to five projects. | Griff Green |
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

Steps 1 to 5, 7 and 8 exist in the web service as built. The service is not deployed, so nobody outside the team has followed them. Steps 9 and 10 are done by people.

| Step | Who | Time |
|---|---|---|
| 1. A contact person creates an account. | Organisation | 5 minutes |
| 2. They enter the domain, and optionally the GitHub organisation name and the Safe addresses. | Organisation | 5 minutes |
| 3. They add the DNS record shown on screen to prove control of the domain. No scan of any depth runs before this. | Organisation, whoever manages DNS | 10 minutes, plus waiting for DNS |
| 4. The first scan runs. | Service | Minutes |
| 5. They choose the depth of scan: passive only, probe, or active. | Organisation | 2 minutes |
| 6. Optionally they supply a list of staff email addresses, so that breach findings can tell current staff from former staff and shared mailboxes. If the own-key route for breach data is chosen, they also supply a key. Supplying a key for each organisation is not built. | Organisation | 10 minutes |
| 7. They choose how often scans run (daily, every 3 days, weekly, or on request only) and where alerts go (email, Slack, Discord or Telegram). | Organisation | 5 minutes |
| 8. Scheduled scans begin. The 60-day period is counted from the first one. | Service | |
| 9. A 30-minute call to read the first report together and agree which findings to fix first. | Both | 30 minutes |
| 10. A check-in at 30 days. | Both | 15 minutes |

Step 9 matters most. A report that nobody reads produces no fixes.

To leave, the organisation removes the domain in the service. Its scans, findings and verification record are deleted at once. Audit log entries remain. Removing the DNS record alone withdraws authorisation: active checks and per-person detail stop, and standing is withdrawn after three failed daily checks.

Today each account is its own organisation. Inviting colleagues is not built and is part of Milestone 1. Until then a team shares one sign-in address.

## How adoption is measured

| Measure | Definition | Counted by |
|---|---|---|
| Verified organisation | An organisation whose domain control has been proved and is still proved | The service, at each scan |
| Monitored for 60 consecutive days | At least 60 days between the first and the latest scheduled scan, with verification in force throughout and no gap between scans longer than **[TODO: suggested 8 days, which allows the weekly schedule, the longest the service offers]** | The service, from the scan history |
| Documented fix | A finding reported in one scan and recorded as resolved in a later scan in which the relevant check ran to completion | The engine's scan comparison, which is built |
| Time to fix | Days between the scan that first reported a finding and the scan that recorded it as resolved | The service |
| Integration | As defined in `05-milestones-budget.md` | Evidence from the other party |

The rule about checks running to completion is important for honest counting. The engine already applies it: if a check was skipped or failed, its earlier findings are carried forward as stale and are not counted as fixed.

## How adoption is evidenced to the reviewer

A reviewer should not have to take the team's word.

| Claim | Evidence | Can the reviewer check it independently? |
|---|---|---|
| Organisation X uses the service | The DNS record at `_parapet-verify.<domain>` | Yes, by a public DNS query |
| Organisation X is a real, independent user | Written confirmation from a named contact person at X | Yes, by contacting them |
| X was monitored for 60 consecutive days | Scan history for X, with dates | Partly. The history is held by the service. The contact person can confirm. |
| X fixed finding Y | The scan comparison showing Y reported and later resolved | Yes for findings based on public records, such as email and DNS settings. The reviewer can query the present state. For other findings, the contact person can confirm. |
| The integration is in production | A demonstration with real data from a consenting organisation, and written confirmation from the other party | Yes |

### Confidentiality

The reviewer sees the names of all N organisations and the kind of each fix. The reviewer does not need to see the findings themselves, and organisations must agree before any finding is shown to the reviewer.

At least half of the organisations are asked to agree to be named publicly. The others are named to the reviewer only. Some organisations will not want to say in public that they use a security monitoring service, and that is a reasonable position.

**[TODO: prepare a one-page consent form for organisations, covering: being named to the reviewer, being named publicly (optional), and having the kinds of fix counted in the public report. Have the lawyer review it with the other documents in Milestone 2.]**

## The integration

One integration is required. Candidates, in order of how directly they follow from work already done:

1. **An assessor uses the reports as evidence.** A SEAL-accredited assessor or OpSec auditing firm accepts Parapet reports for the DNS and email controls in a real assessment. The JSON output and schema are built. What is needed is a firm willing to try it and a mapping from findings to controls, which is not built.
2. **A rating body consumes the JSON output.** This depends on the OPSEC Ratings Coalition being formed and choosing to do so. The timing is outside the team's control.
3. **Another tool imports the JSON output.** **[TODO: name a candidate tool if you have one in mind.]**

**[TODO: choose the primary candidate and start the conversation during Milestone 1. Integrations depend on another party's timetable and are the part of Milestone 3 most likely to run late.]**

## After the milestone

The public report from Milestone 3 gives totals: organisations, scans, findings by kind, fixes by kind and median time to fix. It names no findings for any organisation. These totals would be the first public figures on the outside-in exposure of small crypto organisations that have opted in, and they are useful to SEAL, to the ratings coalition and to the fund when it decides what to pay for next.

## Notes for the maintainer (delete before submitting)

- The funnel numbers are guesses. Say so if asked.
- An organisation that chooses "on request only" has no scheduled scans and would not count towards N. Say so during onboarding.
