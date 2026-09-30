> Ready for the maintainer's review. Not yet submitted.

# Grant resubmission: Perimeterwatch

The resubmission to TheDAO Security Fund, Round Two "ETHSecurity Initiatives". Contact at the fund: Griff Green.

The text that goes into the fund's form is `SUBMISSION.md`. The same text laid out for reading is `10-resubmission.md`. Files `01` to `09` are longer background and still carry blanks for the maintainer.

## What changed since the first submission

The first submission, on 9 September 2026, was called xWatch. The reviewer's feedback had three points. The resubmission answers each one.

| Feedback | Where it is answered |
|---|---|
| The prototype was not solid enough to justify a grant instead of an RFP | "Why a grant: what already exists" in `10-resubmission.md`, with `03-solution.md` and `04-team.md` behind it. The service is live in beta at https://perimeterwatch.org and the code is public. |
| The adoption milestone should be 50% of the ask | The adoption milestone is $75,000 of $150,000. See `10-resubmission.md` and `05-milestones-budget.md`. |
| The summary did not say clearly what the thing is | The short summary and "Why this matters" in `10-resubmission.md` each open with what it is. `01-summary.md` has longer and shorter versions. |

## Files

| File | Contents |
|---|---|
| `01-summary.md` | What it is, who it is for, what exists, the ask. Also a one-sentence and a tweet-length version. |
| `02-problem.md` | Verified incidents that started outside the smart contracts, each with a source. Why small teams lack visibility. |
| `03-solution.md` | What is checked, the consent model, what the tool will not do, built versus planned. |
| `04-team.md` | Why this team. Mostly blanks for the maintainer to fill. |
| `05-milestones-budget.md` | The four milestones with the working checks behind each criterion, a worked budget at $150,000, recurring costs. |
| `06-positioning.md` | Relation to the OPSEC Ratings Coalition, the two Auditware initiatives, SEAL, and commercial tools. |
| `07-cofunding.md` | Who benefits, who might pledge, and an outreach message. |
| `08-risks.md` | Each risk, its mitigation, and what remains unsolved. |
| `09-adoption-plan.md` | How to reach the adoption target and how it is evidenced. |
| `10-resubmission.md` | **The submission itself**, in the structure of the fund's form as read on 30 September 2026. Start here. The other files are longer background for each section. |
| `SUBMISSION.md` | The same text as one block per form field, ready to paste, with the steps for pasting. |

## How to use these

1. Read `10-resubmission.md`. It has no blanks. Check every claim in it against what you know.
2. Read its short summary aloud to someone outside security. If they cannot say back what the project is after the first two sentences, rewrite those sentences before anything else.
3. The numbers are set: $150,000 over 6 months, four milestones of $30,000, $30,000, $75,000 and $15,000, at least 25 organisations, at least 10 of them securing over $1 million onchain, and at least 30 fixes. The reasoning is in `05-milestones-budget.md`. If you change one, that file lists the others to change with it.
4. Do the items under "Before submitting" below.
5. Follow the steps in `SUBMISSION.md` to paste the text into the form at https://initiatives.thedao.fund/submit. The form sorts a pasted draft into its fields by heading. Its field names and rules are described in the fund's drafting guide, which the submission page offers to copy.
6. Files `01` to `09` still contain `[TODO:` marks. They are background and are not pasted into the form. Fill them before pointing a reviewer at them.

## Blanks you must fill

The form has two private fields that are not written in this repository: "Who is likely to fund this?" and "Contact". Both are required.

The blanks below are in the background files.

| Blank | File |
|---|---|
| Your biography, prior work, public profiles | `04-team.md` |
| Second maintainer, or a statement that there is none yet | `04-team.md`, `08-risks.md` |
| Legal entity (the non-profit), jurisdiction, status | `04-team.md`, `05-milestones-budget.md` |
| Your monthly rate and hours available | `05-milestones-budget.md` |
| Quotes for the security review and the legal review | `05-milestones-budget.md` |
| Outcome of the email to Have I Been Pwned | `08-risks.md`, `05-milestones-budget.md` |
| Pilot organisations already in conversation, if any | `04-team.md`, `09-adoption-plan.md` |
| Named candidate co-funders and any pledges | `07-cofunding.md` |
| Candidate integration partner. An integration is an aim, not a payment criterion | `05-milestones-budget.md`, `09-adoption-plan.md` |
| Proposed independent reviewer, if the fund asks you to suggest one | `05-milestones-budget.md` |
| Questions for the fund (prepayment wording, whether a security review is fundable) | `05-milestones-budget.md` |
| How the gap between spending and payments is covered before the adoption milestone pays | `05-milestones-budget.md` |

## Before submitting

These are actions, not text edits.

- Open every link in `SUBMISSION.md` on the day you submit and check that it loads: the service, the repository, the sample report, the legal drafts at https://perimeterwatch.org/legal, and the news sources.
- Check that the numbers in the submission still match the repository and the service: 34 checks of which 33 run in the beta, 104 kinds of finding, 10 pinned tools, 2,560 tests. The test count rises with each change, so read it from the latest public CI run.
- The repository, its public CI, the sample report and the beta are all in place, so Milestone 1 pays for what remains before review: backups, monitoring, the missing parts of the onboarding flow, and a tagged 1.0 release. The independent security assessment is in Milestone 2.
- After fixing the findings in the sample report, publish the second report, which shows them as resolved.
- Record a short screen capture of `pwatch` scanning that domain.
- Send the email to Have I Been Pwned (see `08-risks.md`).
- Ask at least two organisations whether they would pilot the web service, so that `09-adoption-plan.md` names real conversations.

## Dates from the fund's announcement

- Round Two opened on 15 September 2026.
- Badge holders allocate remaining funds in mid-November 2026.
- The round closes at the end of January 2027.

Source: https://paragraph.com/@thedao.fund/round-two-starts-today-ethsecurity-initiatives
