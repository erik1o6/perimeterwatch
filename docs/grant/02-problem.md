> Draft for review and editing. Not yet submitted.

# The problem

## In one paragraph

Crypto organisations spend most of their security budget on smart contract audits. Many of the losses of recent years did not start in a smart contract. They started with a domain registrar account, a website script, a staff laptop, a published key, or a new hire who was not who they claimed to be. Large organisations pay for monitoring that watches these things from the outside. Small teams usually do not, and often do not know what an outsider can see about them.

## Incidents that started outside the smart contracts

Each incident below was checked against the linked source on 29 September 2026. Loss figures are as reported by the source and are approximate.

### Domain and DNS hijacks

| Date | Organisation | What happened | Reported loss | Source |
|---|---|---|---|---|
| August 2022 | Curve Finance | The DNS for curve.fi was changed to point at a copy of the site that asked users to approve a malicious contract. | About $575,000 | [rekt.news](https://rekt.news/curve-finance-rekt) |
| September 2023 | Balancer | Attackers used social engineering against the domain registrar, took control of balancer.fi, and served a site that drained wallets. | About $238,000 | [Balancer post mortem](https://medium.com/balancer-protocol/dns-security-incident-post-mortem-1b1feb735aca), [Cointelegraph](https://cointelegraph.com/news/balancer-social-engineering-attack-dns-provider-frontend-hijack) |
| July 2024 | Compound Finance, Celer Network, Pendle and others | Domains moved from Google Domains to Squarespace lost their two-factor protection in the move. Attackers took over registrar accounts and changed DNS records. A public list named more than 100 crypto domains at risk. | Varies by project; Pendle reported none | [Krebs on Security](https://krebsonsecurity.com/2024/07/researchers-weak-security-defaults-enabled-squarespace-domains-hijacks/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/dns-hijacks-target-crypto-platforms-registered-with-squarespace/) |
| November 2025 | Aerodrome and Velodrome | The domains of both exchanges were hijacked and visitors were sent to phishing pages. The teams stated that the smart contracts were not affected. | Reports range from about $700,000 to over $1 million | [CoinDesk](https://www.coindesk.com/web3/2025/11/22/aerodrome-finance-hit-by-front-end-attack-users-urged-to-avoid-main-domain), [The Block](https://www.theblock.co/news/ecosystems/2025-11-22-top-dexs-aerodrome-velodrome-hit-with-front-end-compromise-urge-users-to-avoid-main-domains-380037) |

### Compromised website code

| Date | Organisation | What happened | Reported loss | Source |
|---|---|---|---|---|
| November to December 2021 | BadgerDAO | An attacker used a compromised Cloudflare API key to add a script to the website. The script asked users for token approvals. It ran for weeks before discovery. | About $120 million | [CoinDesk](https://www.coindesk.com/business/2021/12/10/badgerdao-reveals-details-of-how-it-was-hacked-for-120m), [Halborn](https://www.halborn.com/blog/post/explained-the-badgerdao-hack-december-2021) |
| December 2023 | Ledger Connect Kit | A former Ledger employee was phished. Their access to the package registry had not been revoked when they left. The attacker published a malicious version of a library used by many applications. | About $600,000 | [Ledger incident report](https://www.ledger.com/blog/security-incident-report) |
| February 2025 | Bybit, through Safe{Wallet} | A Safe{Wallet} developer's laptop was compromised. The attackers changed the website code that Bybit's signers used, so that the signers approved a transaction different from the one shown. | About $1.5 billion | [The Hacker News](https://thehackernews.com/2025/03/safewallet-confirms-north-korean.html) |

### Phished or infected staff

| Date | Organisation | What happened | Reported loss | Source |
|---|---|---|---|---|
| March 2022 | Ronin bridge (Sky Mavis) | A senior engineer was approached with a fake job offer and opened a document that installed spyware. The attackers then took over validator keys. | Reported between $540 million and $625 million | [The Block](https://www.theblock.co/post/156038/how-a-fake-job-offer-took-down-the-worlds-most-popular-crypto-game), [The Hacker News](https://thehackernews.com/2022/07/hackers-used-fake-job-offer-to-hack-and.html) |
| October 2024 | Radiant Capital | A developer received a file over Telegram from someone posing as a former contractor. It installed malware. Signers saw legitimate transaction data while signing malicious transactions. | About $50 million | [Radiant incident update](https://medium.com/@RadiantCapital/radiant-capital-incident-update-e56d8c23829e), [CoinDesk](https://www.coindesk.com/tech/2024/12/09/radiant-capital-says-north-korean-hackers-behind-50-million-attack-in-october) |

### Keys published by mistake

| Date | Organisation | What happened | Reported loss | Source |
|---|---|---|---|---|
| June 2024 | An individual developer | A developer published a wallet's private key in a public GitHub repository. The wallet was emptied within about two minutes. | About $48,000 | [Web3 Is Going Just Great](https://www.web3isgoinggreat.com/?id=br1aneth-private-key-compromise) |
| June 2026 | Taiko | A private signing key was published by mistake in a public GitHub repository. An attacker used it to forge proofs and withdraw assets. | About $1.7 million | [Incrypted](https://incrypted.com/en/ledger-cto-private-key-leak-caused-taiko-hack/) |

### Fake IT workers

| Date | Organisation | What happened | Reported loss | Source |
|---|---|---|---|---|
| March 2024 | Munchables | Developers hired by the project, later suspected to be one person linked to North Korea, had kept control of the contract and took the funds. The funds were returned. | About $62.5 million taken, then returned | [CoinDesk](https://www.coindesk.com/tech/2024/03/27/munchables-exploited-for-62m-ether-linked-to-rogue-north-korean-team-member), [Halborn](https://www.halborn.com/blog/post/explained-the-munchables-hack-march-2024) |
| August 2024 | More than 25 projects | The investigator ZachXBT traced a group of 21 developers, working under false identities, across more than 25 crypto projects. One project lost $1.3 million after the developers pushed malicious code. | $1.3 million in the case that started the investigation | [CryptoSlate](https://cryptoslate.com/zachxbt-exposes-north-korean-agents-infiltrating-crypto-projects-to-conduct-thefts/), [CoinDesk](https://www.coindesk.com/tech/2024/10/02/how-north-korea-infiltrated-the-crypto-industry) |

## The wider numbers

Chainalysis reported that more than $3.4 billion was stolen from crypto services and wallets in 2025, that the Bybit theft was about 44% of that, and that at least $2.02 billion was attributed to North Korean groups. Source: [Chainalysis](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2026/), [The Record](https://therecord.media/over-3-billion-crypto-stolen-2025-north-korea).

## What this project would and would not have caught

This section is here so that the proposal does not claim too much.

Perimeterwatch looks from the outside. It does not run on staff devices and it does not watch a registrar account from the inside.

| Kind of incident | What Perimeterwatch does about it | What it does not do |
|---|---|---|
| DNS hijack | Reports weak settings beforehand (no DNSSEC, no CAA record, all nameservers with one provider). At the next scan it reports new findings, such as DNSSEC having been switched off, and hosts that have appeared or disappeared. | It does not prevent a registrar account from being taken over. It does not today record every change to the value of a DNS record. Detection is only as fast as the scan interval, which is one day at the shortest. |
| Compromised website code | None of the current checks inspect website scripts. | It would not have detected the BadgerDAO, Ledger or Safe{Wallet} script changes. |
| Phished or infected staff | Reports staff addresses that appear in known breaches and in logs from password-stealing malware, which shows who is likely to be targeted or already infected. For malware logs it names the critical services involved, such as GitHub or Safe. Reports whether the domain's email can be forged. | It does not stop someone opening a malicious file. That is the job of device protection such as the Auditware EDR initiative. |
| Keys published by mistake | Scans the organisation's public GitHub repositories for committed secrets. | It only sees public repositories of the organisation's own GitHub account. It does not see staff members' personal repositories. |
| Fake IT workers | None. | The tool does not profile individuals, by design. |
| Signer changes on a treasury | Reads the owners and threshold of the organisation's Safe from the chain and reports any change. | It reports the change after it has happened. It does not block it. |

The honest summary: this is a visibility tool. It is the least intrusive kind of security measure, and that is why the barrier to adopting it is low. It shortens the time during which a team is exposed without knowing it. It does not replace device protection, registrar hardening or audits.

## Why small teams lack this visibility

1. **Cost.** Commercial outside-in monitoring is priced for companies with security budgets. Published prices and sources are in `06-positioning.md`.
2. **No one owns it.** In a team of five to twenty people, the domain was registered by a founder, the email was set up by whoever was there at the time, and the GitHub organisation grew on its own. Nobody has the job of looking at the whole picture.
3. **The free tools exist but are separate.** Every check in Perimeterwatch can be done by hand with free tools. Doing so requires knowing that the tools exist, installing each one, understanding the output, and repeating it regularly. In practice small teams do this once or never.
4. **Crypto-specific items are not covered by general products.** General monitoring products are not built around a treasury's signer list.
5. **Audits look elsewhere.** A smart contract audit does not examine email settings or DNS records. A team can hold several audit reports and still have a domain whose email anyone can forge.
6. **Fear of what scanning involves.** Teams are wary of anything that scans them. A tool that looks only at public records by default, and asks for proof of ownership before doing more, removes that objection.

## Notes for the maintainer (delete before submitting)

- The Taiko incident rests on one news source, which reports both the Ledger CTO's analysis and Taiko's confirmation. If you want a second source, look for Taiko's own statement and link it.
- The Ronin loss is reported differently by different outlets because of price changes. The table gives the range.
- If you know of an incident from your own experience, add it only with a public source.
