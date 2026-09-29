> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Privacy policy

Status: draft for the hosted service. The service has been built but is not yet deployed or open to outside organisations.

Last updated: **[TO DECIDE: date]**

## 1. The short version

- An organisation asks us to look at what outsiders can see about its own systems.
- Most of what we collect is technical: hostnames, DNS records, certificates.
- Some of it is about people. The main case is this: if your work email address appears in a known data breach, your employer can see that fact, and the name of the breach.
- We never hold your password, a hash of your password, or anything else that was taken in a breach.
- Findings about individual people are produced only for an organisation that has proved it controls the domain. We do not publish anything.
- We do not look at social media. We do not build profiles of people.
- The service's pages use no JavaScript, no analytics and nothing loaded from other companies.

## 2. Who is responsible for your data

Two terms from data protection law are used in this policy.

- A **controller** decides why and how personal data is used.
- A **processor** handles personal data for a controller, on the controller's instructions.

**The operator** is **[TO DECIDE: legal name of the operating entity]**, established in **[TO DECIDE: jurisdiction]**. "We" means the operator.

**The customer** is the organisation that uses the service to check its own domain. If you are reading this because your employer uses the service, your employer is the customer.

| Data | Controller | Processor |
|---|---|---|
| Data about a customer's staff found by a scan, or supplied by the customer | The customer | The operator |
| Account details of the people who sign in to the service for a customer | The operator | None |
| Details of people who send us an abuse report, an opt-out request or a security report | The operator | None |

**[LAWYER: confirm this split. See README open question 1.]**

## 3. What personal data is handled

### 3.1 Data about staff of a customer

| Category | What exactly is stored | Where it comes from |
|---|---|---|
| Work email addresses found in data breaches | The address, the name of the breach, the date of the breach, and the kinds of data the breach contained (for example "email addresses, passwords"). | Have I Been Pwned |
| Work email addresses found in malware logs | The address. The names of websites the captured logins were for, but only for two kinds of site: the organisation's own systems, and a fixed list of services that control code, infrastructure or funds. A count of all other sites. | Have I Been Pwned |
| Staff list | Work email addresses at the customer's own domain. Addresses at any other domain are rejected. | Supplied by the customer. This is optional. |
| Whether an address is on the staff list | "Yes" or "no", added to each breach finding when the customer has supplied a staff list. | Worked out by the service |

A **malware log** is a record made by malicious software on an infected device. The software captures logins typed or saved on that device. We never receive or store the logins themselves.

**What is never stored:** passwords, password hashes, security answers, or any other value that was exposed in a breach or captured by malware. The software has no field that could hold one.

**The fixed list of services** is: GitHub, GitLab, npm, Google accounts, Microsoft sign-in, Okta, Amazon Web Services, Cloudflare, Vercel, Namecheap, GoDaddy, Safe, Fireblocks, 1Password, Slack, Discord, X (Twitter) and Telegram. The names of all other websites are discarded during the scan and are never stored.

**Things you should know:**

- Your employer sees the name of each breach your work address appears in. If you used your work address to sign up to a personal site and that site was breached, the name of the breach may show it. The service does not filter breach names. **[LAWYER: see README open question 3.]**
- A malware log finding suggests that a device you used was infected. It may have been your own device.
- The staff list can be loaded with the command-line tool only. **[NOT YET BUILT: loading a staff list in the hosted service.]**

### 3.2 Other data that may relate to a person

| Category | What exactly is stored | Where it comes from |
|---|---|---|
| Blockchain addresses | The owner addresses and the signing threshold of a Safe multisig wallet named by the customer. | The public blockchain, read through an RPC provider |
| Credentials found in public code | The type of credential, the repository, file, line, commit and commit date, the first four characters, and a short hash. The credential itself is never stored and never tested. The committer's email address is discarded. | The customer's public GitHub repositories |
| Hostnames and certificates | Names of hosts under the customer's domain. A hostname can contain a person's name if the customer chose it that way. | Certificate transparency logs, passive DNS indexes, public DNS |
| Job postings | Only the names of technologies mentioned in the customer's own public job postings. Nothing about applicants or staff. | Greenhouse or Lever public job boards |
| Lookalike domains | Domain names that resemble the customer's, with their DNS records. No registrant details are collected. | Public DNS, certificate transparency logs |
| Aggregate malware counts (optional, off by default) | Three numbers for the domain: staff devices, customer devices and third-party devices seen in malware logs. No addresses. | Hudson Rock |

### 3.3 Data about people who use the service

| Category | What is stored | How long |
|---|---|---|
| Account | Email address, date the account was created, time of last sign-in, role in the organisation. | Life of the account. **[NOT YET BUILT: closing an account.]** |
| Sign-in link requests | The email address typed, the network address (IP address) of the requester, the time, and a hash of the link's token. The token itself is not stored. This is stored even if no account exists for the address. | Until one day after the link expires. A link expires after 15 minutes. |
| Sessions | A hash of the session cookie, the network address and browser identification at sign-in, time of sign-in, time last seen. | Until the session ends: after 12 hours without use, or 7 days, or at sign-out. |
| Audit log | Who did what and when. For actions in the hosted service: the user's email address, network address and browser identification. See 3.4. | **[TO DECIDE: audit log retention period.]** It is not pruned today. |
| Alert channels | For email: the address to send to. For Slack and Discord: the webhook address. For Telegram: the bot token and chat number. Stored encrypted. | Until the customer removes the channel |
| Alert delivery records | The text of each alert, whether it was sent, and any error. | See the [data retention policy](data-retention-policy.md) |

There are no passwords in the service.

### 3.4 What the audit log records

| Action | What is recorded |
|---|---|
| Signing in and out | The user, and whether it was the first sign-in |
| Adding, changing or removing a domain | The user and the domain |
| Starting or checking domain verification | The user and the result |
| Loss of verification | That it happened. Recorded as done by the system. |
| Requesting a scan, and a scan finishing | The user, the depth |
| Opening a finding about a person or a credential | The user, and the kind of finding. **Not** the name or address of the person the finding is about. |
| Downloading a report | The user, the format, and whether personal details were shown or masked |
| Marking a finding as an accepted risk, or reopening it | The user |
| Adding, testing or removing an alert channel | The user and the kind of channel |

The owner of the organisation's account can read the last 300 entries in the service.

### 3.5 Data about people who contact us

If you send an abuse report, an opt-out request or a security report, we keep what you send and our reply.

## 4. Cookies

| Cookie | Purpose | Lasts |
|---|---|---|
| Session cookie (`__Host-parapet_session`) | Keeps you signed in | 7 days at most |
| Anti-forgery cookie (`parapet_csrf`) | Protects forms shown before sign-in against forged requests | 1 day |

Both are needed for the service to work. Neither is used to track you. The pages load no scripts, no analytics and no resources from other companies. **[LAWYER: see README open question 36.]**

## 5. What we do not do

- We do not scrape LinkedIn or social media.
- We do not build profiles of individuals.
- We do not hold raw breach databases.
- We do not test whether a found credential works.
- We do not produce a score or rating of an organisation or a person.
- We do not publish findings or share them with other customers.
- We do not sell data.
- We do not make automated decisions about people.

## 6. Why the data is used, and the legal basis

| Purpose | Data | Legal basis |
|---|---|---|
| Showing an organisation which of its work accounts are at risk because of a breach, so it can reset passwords and protect accounts | Breach and malware log data, staff list | Decided by the customer as controller. The expected basis is the customer's legitimate interests in network and information security (GDPR Article 6(1)(f), see Recital 49). |
| Showing an organisation what changed since the last scan | All findings | As above |
| Showing who controls the organisation's multisig wallet, and changes to that | Blockchain addresses | As above |
| Showing credentials that were published by mistake | Credential findings | As above |
| Signing users in and keeping them signed in | Account, sign-in link requests, sessions, cookies | **[LAWYER: expected to be performance of contract and the operator's legitimate interests.]** |
| Limiting abuse of the sign-in form | Sign-in link requests, including the network address | **[LAWYER: expected to be the operator's legitimate interests.]** |
| Sending alerts | Alert channels, alert delivery records | **[LAWYER: expected to be performance of contract.]** |
| Keeping a record of actions for security and accountability | Audit log | **[LAWYER: expected to be the operator's legitimate interests, and the customer's.]** |
| Answering abuse reports, opt-out requests and security reports | Contact data | **[LAWYER: expected to be the operator's legitimate interests.]** |

A customer can use the [legitimate interest assessment template](legitimate-interest-assessment.md) to record its own reasoning.

## 7. Who can see the data

- **The customer's users.** Findings about individual people are produced only while the customer's domain is verified. In lists and on scan pages, names and addresses of people are masked: `alice@example.org` appears as `a***@example.org`. The full detail is shown one finding at a time, and each view is recorded in the audit log.
- **Reports.** A report can be downloaded with personal details masked, which is the default, or shown. The choice is recorded in the audit log.
- **The operator's staff**, where needed to run the service. **[TO DECIDE: access rules for operator staff.]**
- **Sub-processors and recipients** listed in section 9.
- **Authorities**, where the law requires it.

**A limit you should know about.** If an organisation loses verification of its domain, its scans stop and findings about people are withheld: they cannot be opened, and a report with personal details shown cannot be downloaded. The stored findings are not deleted until the domain is deleted. Lists still show a masked entry for each, with the name of the breach. **[NOT YET BUILT: deleting them. LAWYER: see README open question 30.]**

## 8. How the data is protected

- Findings, staff lists, verification tokens and alert channel settings are encrypted in the database, field by field. The encryption keys are supplied to the service separately from the database and can be rotated. One set of keys protects all customers' data.
- Findings about individual addresses are matched between scans using a keyed hash, so the address is not used as a plain lookup value.
- Each customer's data carries a tenant identifier, and every query is limited to one tenant. The tenant is taken from the signed-in session and from nowhere else. This separation is enforced by the application, not by the database.
- Sign-in links and session cookies are stored only as hashes.
- An audit log records the actions listed in 3.4.
- Credentials used by the service are kept out of logs.

The service has not had an independent security review.

The full list is in Annex A of the [data processing agreement](dpa-outline.md).

## 9. Sub-processors, recipients and sources

A **sub-processor** is a company that handles personal data for us.

| Role | Company | Location | Personal data it handles |
|---|---|---|---|
| Hosting | **[TO DECIDE: hosting provider]** | **[TO DECIDE]** | All stored data |
| Email (SMTP) | **[TO DECIDE: email provider]** | **[TO DECIDE]** | Account users' email addresses, sign-in links, text of email alerts |
| Ethereum RPC | **[TO DECIDE: RPC provider]** | **[TO DECIDE]** | The wallet addresses being read |

**Alert providers.** These receive data only if a customer sets up a channel of that kind. The customer chooses them and supplies the webhook address or bot token.

| Provider | What it receives |
|---|---|
| Slack | The text of each alert |
| Discord | The text of each alert |
| Telegram | The text of each alert, and the chat number |
| The email provider of the address the customer names | The text of each alert |

Alert text holds: the customer's domain name, the severity and title of findings that are not about a person or a credential (a title can include a host name), counts, and a link to the scan. For a finding about a person, the alert says only "A staff address in breach data". For a credential, it says only "A credential in public code". Alert text never holds a person's name or email address, any part of a credential, or the name of a breach.

**[LAWYER: whether alert providers are sub-processors or recipients chosen by the controller, and transfers. See README open questions 28 and 34.]**

**Sources.** We send them a query and receive data. The query contains the customer's domain name or organisation name, not personal data about staff.

| Source | What we send | What we receive |
|---|---|---|
| Have I Been Pwned | The customer's domain | Addresses at that domain, breach names, website names from malware logs |
| crt.sh | The customer's domain and name | Certificates and the hostnames in them |
| Sources behind subfinder: **[TO DECIDE: list of enabled sources]** | The customer's domain | Hostnames |
| GitHub | The customer's GitHub organisation name | Public organisation details and public repositories |
| Greenhouse or Lever | The customer's job board name | Public job postings |
| Public DNS resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9) | Hostnames | DNS records |
| Hudson Rock (off by default) | The customer's domain | Counts only |

## 10. Have I Been Pwned attribution

Breach data from Have I Been Pwned (haveibeenpwned.com), licensed CC BY 4.0.

Licence text: https://creativecommons.org/licenses/by/4.0/

This attribution appears on every finding and in every report that contains breach data. Anyone who shares that data must keep it.

Have I Been Pwned's terms do not allow its data to be used to build a breach search service. For that reason, breach findings are produced only for an organisation that has verified the domain.

**[LAWYER and TO DECIDE: the arrangement with Have I Been Pwned is not settled. See README open question 8.]**

## 11. Transfers to other countries

Data is stored in **[TO DECIDE: storage region or regions]**.

**[TO DECIDE: whether any sub-processor, alert provider or source is outside the EEA or UK, and the transfer mechanism used for each. LAWYER: see README open question 28.]**

## 12. How long data is kept

The default period is 90 days. **[TO DECIDE: whether a customer can change it. Today it is one setting for the whole service.]**

- Scans older than the period are deleted, with their findings. The most recent scan of each domain is kept longer, so that the next scan can be compared with it.
- A finding that has been resolved for longer than the period is deleted.
- A finding that is still open is kept for as long as it stays open.
- The service does this automatically, at most every six hours.

When a customer deletes a domain, the scans, findings, staff list and verification records for that domain are deleted at once. Audit log entries are kept.

The [data retention policy](data-retention-policy.md) has the full table.

## 13. Your rights

Depending on where you live, you may have the right to:

- know whether data about you is held, and get a copy;
- have wrong data corrected;
- have data deleted;
- have the use of data restricted;
- object to the use of data that is based on legitimate interests;
- complain to a data protection authority.

### If you work for a customer

Your employer is the controller. Send your request to your employer first. It knows who you are and can act on your request.

If you write to us instead, this is what we do:

1. We do not confirm or deny to you that your employer is a customer, unless your employer has agreed that we may.
2. We pass your request to the customer that controls the domain of your work address, without delay.
3. We help that customer answer you. This is part of our agreement with it.

If your employer does not answer, you can complain to your data protection authority. **[LAWYER: see README open question 29.]**

**Limits you should know about.**

- The service cannot yet delete or export the records about one person only. **[NOT YET BUILT.]** Your employer can delete the whole domain, which deletes every finding for it.
- Deleting a finding about your address does not remove your address from the breach. The breach happened elsewhere. If the domain is scanned again, the same finding will come back.

### If you are an account user, or you contacted us

We are the controller. Write to **[TO DECIDE: privacy contact address]**.

The service has no function to close an account yet. We act on your request by hand. **[NOT YET BUILT.]**

We answer within one month. **[LAWYER: confirm period for the chosen jurisdiction.]**

## 14. Contact

| | |
|---|---|
| Operator | **[TO DECIDE: legal name of the operating entity]** |
| Postal address | **[TO DECIDE: registered address]** |
| Privacy contact | **[TO DECIDE: privacy contact address]** |
| Data protection officer | **[TO DECIDE: whether one is appointed, and contact]** |
| Representative in the EU or UK | **[TO DECIDE: whether one is needed, and contact]** |
| Supervisory authority | **[TO DECIDE: authority name]** |

## 15. Changes to this policy

We will publish changes on this page and show the date. If a change affects how staff data is used, we will tell customers before it takes effect, with **[TO DECIDE: notice period]** notice.

**[NOT YET BUILT: a link to this policy from the service's pages.]**
