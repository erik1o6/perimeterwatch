> Draft for review and editing. Not yet submitted.

# Grant resubmission: Parapet

Drafts for the resubmission to TheDAO Fund, Round Two "ETHSecurity Initiatives". Contact at the fund: Griff Green.

## What changed since the first submission

Griff's feedback had two parts. These drafts answer each one.

| Feedback | Where it is answered |
|---|---|
| The prototype was not solid enough to justify a grant instead of an RFP | `03-solution.md` (section "What exists today and what the grant pays for") and `04-team.md`. The command-line tool and the web service are both built. |
| The adoption milestone should be 50% of the ask | `05-milestones-budget.md` (Milestone 3 is 50%) |
| The summary did not say clearly what the thing is | `01-summary.md` (the first two sentences say what it is) |

## Files

| File | Contents |
|---|---|
| `01-summary.md` | What it is, who it is for, what exists, the ask. Also a one-sentence and a tweet-length version. |
| `02-problem.md` | Verified incidents that started outside the smart contracts, each with a source. Why small teams lack visibility. |
| `03-solution.md` | What is checked, the consent model, what the tool will not do, built versus planned. |
| `04-team.md` | Why this team. Mostly blanks for the maintainer to fill. |
| `05-milestones-budget.md` | Three milestones with pass/fail criteria, a worked budget at a placeholder total, recurring costs. |
| `06-positioning.md` | Relation to the OPSEC Ratings Coalition, Auditware EDR, SEAL, and commercial tools. |
| `07-cofunding.md` | Who benefits, who might pledge, and an outreach message. |
| `08-risks.md` | Each risk, its mitigation, and what remains unsolved. |
| `09-adoption-plan.md` | How to reach the adoption target and how it is evidenced. |

## How to use these

1. Search every file for `[TODO:`. Each one marks something only you can supply. Nothing should be submitted with a blank still in it.
2. Read `01-summary.md` aloud to someone outside security. If they cannot say back what the project is after the first two sentences, rewrite those sentences before anything else.
3. Decide the three numbers that are yours to set: the total ask, N (organisations) and M (documented fixes). Suggested starting values and the reasoning are in `05-milestones-budget.md`. When you change the total, update it in `01-summary.md`, `05-milestones-budget.md` and `07-cofunding.md`.
4. Do the items under "Before submitting" below. Several of them turn a claim into something a reviewer can check.
5. The fund's submission form is at https://initiatives.thedao.fund/submit. The fund's announcement says to copy its AI guide, talk it through with an LLM, and paste the result into the form. Use these files as the source material for that conversation.

## Blanks you must fill

| Blank | File |
|---|---|
| Total ask in USD | `01-summary.md`, `05-milestones-budget.md`, `07-cofunding.md` |
| N and M for the adoption milestone | `05-milestones-budget.md`, `09-adoption-plan.md` |
| Public repository URL and a published sample report, once they exist | `03-solution.md`, `04-team.md`, and then `01-summary.md` |
| Your biography, prior work, public profiles | `04-team.md` |
| Second maintainer, or a statement that there is none yet | `04-team.md`, `08-risks.md` |
| Legal entity (the non-profit), jurisdiction, status | `04-team.md`, `05-milestones-budget.md` |
| Your monthly rate and hours available | `05-milestones-budget.md` |
| Quotes for the security review and the legal review | `05-milestones-budget.md` |
| Whether to keep wallet sign-in in Milestone 1 | `05-milestones-budget.md` |
| Outcome of the email to Have I Been Pwned | `08-risks.md`, `05-milestones-budget.md` |
| Whether the service is free to organisations, and how it is paid for after the grant | `05-milestones-budget.md`, `07-cofunding.md` |
| Pilot organisations already in conversation, if any | `04-team.md`, `09-adoption-plan.md` |
| Named candidate co-funders and any pledges | `07-cofunding.md` |
| Candidate integration partner for Milestone 3 | `05-milestones-budget.md`, `09-adoption-plan.md` |
| Proposed independent reviewer, if the fund asks you to suggest one | `05-milestones-budget.md` |
| Questions for Griff (prepayment wording, whether a security review is fundable) | `05-milestones-budget.md` |

## Before submitting

These are actions, not text edits.

- Consider publishing the repository before submitting, even though publication is also the first item of Milestone 1. The licence file, README, security policy and CI workflow are written. Nothing has been committed or published, and the CI workflow has never run. A reviewer who is asked to believe in a prototype will want to see it. If you publish first, reword criteria 1.1 to 1.3 in `05-milestones-budget.md` so that Milestone 1 does not claim work already done.
- The same applies to one sample report (HTML and JSON) from a scan of a domain you own. A reviewer who can open a real report understands the project faster than from any description.
- Update `docs/legal/README.md`, which still says the hosted service does not exist.
- Record a short screen capture of `parapet` scanning that domain.
- Send the email to Have I Been Pwned (see `08-risks.md`).
- Ask at least two organisations whether they would pilot the web service, so that `09-adoption-plan.md` names real conversations.

## Dates from the fund's announcement

- Round Two opened on 15 September 2026.
- Badge holders allocate remaining funds in mid-November 2026.
- The round closes at the end of January 2027.

Source: https://paragraph.com/@thedao.fund/round-two-starts-today-ethsecurity-initiatives
