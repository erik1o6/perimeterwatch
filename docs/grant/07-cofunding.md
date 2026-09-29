> Draft for review and editing. Not yet submitted.

# Co-funding

## How the fund treats co-funding

The Round Two announcement describes co-funding as a test of real need: "If the potential beneficiaries of a piece of security work are willing to overcome the natural free-rider tendency and fund it, that's a strong signal." It also says: "If the teams that would benefit from a piece of security work won't chip in for it, then either it's the wrong solution or they don't think it's urgent or maybe they are asking for too much money."

Companies pledge to a specific initiative. Pledges are collected only once the initiative is fully funded. If the initiative is not funded by the end of the round, pledges are never collected.

Source: https://paragraph.com/@thedao.fund/round-two-starts-today-ethsecurity-initiatives

## An honest difficulty

The organisations that benefit most from Parapet are small teams without a security budget. They are the least able to pledge. Asking them for money would contradict the purpose of the project.

So the co-funding case rests on a different group: larger organisations that are harmed when the small teams around them are compromised. The small teams can contribute something else, which is a written commitment to use the service. That commitment supports the adoption milestone and shows need in a way the fund can check.

## Who benefits and might pledge

No organisation in this table has been approached or has agreed to anything. The table lists kinds of organisation and the reason each has an interest. **[TODO: replace each kind with named organisations you can reach, and record the state of each conversation.]**

| Kind of organisation | Why they benefit | What to ask for | Named candidates |
|---|---|---|---|
| Layer 2 networks and ecosystem foundations | A compromised project on their network harms their users and their reputation. | A pledge, and an introduction to the projects in their ecosystem | **[TODO]** |
| Multisig and wallet infrastructure providers | Their product is blamed when a customer's signer is compromised. Monitoring of signer changes supports their customers. | A pledge, or engineering help with the signer check | **[TODO]** |
| Large DeFi protocols | They depend on smaller protocols through integrations and shared liquidity. | A pledge | **[TODO]** |
| Venture funds and accelerators with crypto portfolios | One subscription-free tool for every company in the portfolio. They carry the loss when a portfolio company is drained. | A pledge, and onboarding of portfolio companies | **[TODO]** |
| OpSec auditing firms | The reports shorten the evidence-gathering part of an assessment. Findings lead organisations to seek an assessment. | A donated or discounted security review of the hosted service, and an integration | **[TODO]** |
| Insurers and risk underwriters for crypto | Outside-in facts about an applicant, supplied with the applicant's consent | A pledge, or an integration | **[TODO]** |
| Small crypto teams | They are the users | No money. A written commitment to pilot the service. | **[TODO]** |

## Pledges in kind

Some contributions are worth more than money and are easier for the giver to approve.

| Contribution | From | Effect on the budget |
|---|---|---|
| The security review in Milestone 2 | A security firm | Removes the largest single external cost. Also resolves the question of whether the fund pays for reviews. The firm must be independent of the team. |
| Breach data access | Have I Been Pwned, or another breach data provider | Removes a recurring cost and resolves the main open risk in `08-risks.md` |
| Hosting credits | A cloud provider or an ecosystem foundation | Removes a recurring cost |
| Legal review | A law firm with a crypto practice | Removes a one-off cost |

## Target

**[TODO: set a co-funding target. A suggestion: 20% to 30% of the total, which at the placeholder of $140,000 is $28,000 to $42,000. State it as "X of the total is sought from co-funders, of which Y is pledged so far". If Y is zero at submission, say zero.]**

## Outreach message to a possible co-funder

Adapt the parts in brackets. Keep it short. The first two sentences say what the thing is, for the same reason as in the summary.

> Subject: Pledge request: open-source exposure monitoring for small crypto teams
>
> Hello [name],
>
> I have built an open-source tool that shows a crypto organisation what an outsider can already see about it: whether its email can be forged, forgotten web addresses someone else could claim, passwords published by mistake in public code, changes to its treasury signers, and staff emails in known data breaches. It tells the organisation when any of that changes. It only looks at organisations that ask.
>
> The software is built: a command-line tool and a web service, with 1,422 passing tests. The web service is not deployed yet. Here is the code and a sample report: [links].
>
> I am applying to TheDAO Fund's ETHSecurity Initiatives round for [amount] to deploy the web service, have it independently reviewed, and offer it to small teams. Half of that amount is paid only if [N] named organisations are using it and have fixed problems it found.
>
> I am writing to you because [one sentence: the specific reason this organisation is affected when small projects around it are compromised].
>
> The fund counts pledges from organisations that would benefit as evidence that the work is needed. A pledge is collected only if the initiative is fully funded. Would [organisation] consider pledging [amount, or a contribution in kind such as a security review]?
>
> I can show you the tool on a call, scanning a domain of mine, in 20 minutes.
>
> code2142
> [contact details]

## Outreach message to a small team

This one asks for a commitment to use the service and asks for no money.

> Subject: Would you pilot a free exposure monitor for [organisation]?
>
> Hello [name],
>
> I have built an open-source tool that shows a crypto team what an outsider can already see about it, and warns when that changes. Examples: whether someone can send email in your name, forgotten web addresses, passwords in public code, changes to your Safe signers.
>
> I am applying for a grant to run it as a web service, after an independent security review. If it is funded, would you be willing to try it on [domain]? You would add one DNS record to prove the domain is yours. You can remove the domain at any time, which deletes its scans and findings. Your findings are visible only to you.
>
> If you agree, may I name [organisation] in the application as a team that intends to pilot it?
>
> You can also run the command-line version yourself today: [link].
>
> code2142
> [contact details]

## Notes for the maintainer (delete before submitting)

- Do not send either message until the repository and the sample report are public. The links carry the message.
- Do not run a scan of an organisation's domain in order to show them their own findings in a first message. Even a passive scan, which reads only public records, would go against the opt-in principle of the project and may be received as a threat.
- Record every answer, including refusals. A refusal with a reason is useful when setting the total.
