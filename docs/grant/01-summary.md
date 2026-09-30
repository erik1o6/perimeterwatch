> Draft for review and editing. Not yet submitted.

# Summary

## The summary (under 250 words)

Perimeterwatch is open-source software for small crypto teams that have no security staff. It shows a team what any stranger on the internet can already find out about it, and warns the team when that changes.

A team enters its own web address and gets back a plain list of weak points, each with a fix. Examples: settings that let anyone send email in the team's name, forgotten web addresses that someone else could claim, passwords published by mistake in public code, changes to who can sign for the treasury, and staff email addresses found in known data breaches.

It only looks at teams that ask. The web service scans nothing until the team proves the web address is its own. There is no score or grade.

**What exists today.** A web service, live in beta at https://perimeterwatch.org since 30 September 2026, and a command-line tool. 34 checks. 2,555 automated tests pass in public. Code: https://github.com/erik1o6/perimeterwatch

**What does not exist yet.** No outside organisation relies on it. It has had no independent security review and no lawyer's review. The breach check is built and switched off.

**What the grant pays for.** An independent security review, hardening and running the service, legal review, a breach data licence, and getting teams onto it.

**The ask.** $150,000 over 6 months, in four milestones. Half is paid only if at least 25 outside organisations are monitored and have fixed at least 30 problems the software found.

**Team.** code2142, author and maintainer.

## One-sentence version

Perimeterwatch is open-source software that shows a small crypto team what outsiders can already see about it (whether its email can be forged, forgotten web addresses, leaked passwords, lookalike domains, treasury signer changes, staff emails in data breaches) and warns the team when that changes.

## Tweet-length version

Perimeterwatch: open-source software that shows a small crypto team what any outsider can already see about it, and warns when that changes. Leaked passwords, forgeable email, forgotten web addresses, treasury signer changes. Only for teams that ask. Beta: perimeterwatch.org

## Notes for the maintainer (delete before submitting)

- Count the words of the summary again after filling the blanks and after any edit. It must stay under 250.
- The first sentence says what it is and who it is for. The second says what it does. Neither uses a technical term. Do not add "OSINT", "attack surface" or "perimeter" to them. Griff's feedback was that he did not understand what the project was until he reached the requirements section.
- The repository link is in "What exists today". The sample report is published at https://github.com/erik1o6/perimeterwatch/tree/main/docs/sample-report. Add its link there if the word count allows. A reviewer who can open a real report will understand the project faster than from any description.
- The web service is live in beta. Do not call it "in production" or "reviewed" until the independent security review is done, and do not say that organisations use it until one outside the team does.
- The text that goes into the fund's form is in `SUBMISSION.md`. This file is the longer background for its summary.
- Check the character count of the tweet-length version after any edit. The limit is 280.
