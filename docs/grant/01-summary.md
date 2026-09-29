> Draft for review and editing. Not yet submitted.

# Summary

## The summary (under 250 words)

Parapet is open-source software for small crypto teams that have no security staff. It shows a team what any stranger on the internet can already find out about it, and warns the team when that changes.

A team enters its own web address and gets back a plain list of weak points, each with a fix. Examples: settings that let anyone send email in the team's name, forgotten web addresses that someone else could claim, passwords published by mistake in public code, changes to who can sign for the treasury, and staff email addresses found in known data breaches.

It only looks at teams that ask. The web service scans nothing until the team proves the web address is its own. There is no score or grade.

**What exists today.** Two working forms of the software: a command-line tool, and a web service with scheduled scans and alerts by email or chat. 543 automated tests pass.

**What does not exist yet.** The code is not published. The web service has never been deployed, has had no independent review, and has no users.

**What the grant pays for.** Publishing the code, deploying the service, an independent security review, legal review, and getting teams onto it.

**The ask.** **[TODO: total in USD]** over **[TODO: duration, suggested 8 months]**, in three milestones. Half is paid only if named organisations have been monitored for 60 consecutive days and have fixed problems the software found.

**Team.** code2142, author and maintainer.

## One-sentence version

Parapet is open-source software that shows a small crypto team what outsiders can already see about it (whether its email can be forged, forgotten web addresses, leaked passwords, lookalike domains, treasury signer changes, staff emails in data breaches) and warns the team when that changes.

## Tweet-length version

Parapet: open-source software that shows a small crypto team what any outsider can already see about it, and warns when that changes. Leaked passwords, forgeable email, forgotten web addresses, treasury signer changes. Only for teams that ask. Built, not yet deployed.

## Notes for the maintainer (delete before submitting)

- Count the words of the summary again after filling the blanks and after any edit. It must stay under 250.
- The first sentence says what it is and who it is for. The second says what it does. Neither uses a technical term. Do not add "OSINT", "attack surface" or "perimeter" to them. Griff's feedback was that he did not understand what the project was until he reached the requirements section.
- Once the repository and a sample report are published, add the two links to "What exists today" and remove "The code is not yet published". A reviewer who can open a real report will understand the project faster than from any description.
- Do not call the web service "live", "hosted" or "running" until it is deployed. It is built and tested. It is not deployed.
- Check the character count of the tweet-length version after any edit. The limit is 280.
