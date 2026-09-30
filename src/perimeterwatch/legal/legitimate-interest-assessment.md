> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Legitimate interest assessment: template

Status: draft template for customers of the hosted service. The service has been live in beta at https://perimeterwatch.org since 30 September 2026. No lawyer has reviewed this template, and the service has had no independent security review. The legal documents are drafts under review and are not yet in force.

Last updated: 30 September 2026

**The breach exposure check is switched off in the hosted service today.** No breach data source is configured, so the processing this template assesses does not take place yet. Customers will be told before the check is switched on. Write your assessment before that date, not after it.

## What this is

Your organisation is the controller for data about your staff. If you rely on "legitimate interests" (GDPR Article 6(1)(f)) to look at your staff's exposure in data breaches, you should be able to show your reasoning. A **legitimate interest assessment** is the written record of that reasoning. It has three parts:

1. **Purpose.** Is there a legitimate interest?
2. **Necessity.** Is this processing needed to achieve it?
3. **Balancing.** Do the interests or rights of the people concerned outweigh it?

## How to use this template

- Copy it into your own records. Remove the banner and this section only after your own adviser has reviewed it.
- Text in plain type describes what the service does. It is the same for every customer. Check it against the current [privacy policy](privacy-policy.md) before you rely on it.
- Text marked **[YOU: ...]** is for you to write. The assessment is yours, not ours. We cannot decide the balance for you.
- If your honest answer to a question is unfavourable, write it down and then decide what to change. An assessment that only records good news is of little use.
- This template covers breach exposure data only. If you also need to assess other findings, add sections.

---

# Legitimate interest assessment

| | |
|---|---|
| Organisation (controller) | **[YOU: legal name]** |
| Processing assessed | Checking work email addresses at **[YOU: domain]** against known data breaches and malware logs, using Perimeterwatch |
| Processor | The operator of Perimeterwatch. There is no legal entity yet. The service is operated by its maintainer, known publicly as code2142, as an individual, while a non-profit entity is being set up. **[TO DECIDE: legal name of the entity, once established]** |
| Assessment written by | **[YOU: name and role]** |
| Date | **[YOU: date]** |
| Approved by | **[YOU: name and role]** |
| Next review | **[YOU: date, no more than 12 months ahead]** |

## Description of the processing

| Question | Answer |
|---|---|
| Whose data? | Anyone with an email address at our domain that appears in breach data. This includes current staff, contractors, former staff, and shared addresses such as `info@`. |
| What data? | The email address. For each breach: its name, its date, and the kinds of data it contained. For malware logs: the names of sites the captured logins were for, but only our own systems and a fixed list of services that control code, infrastructure or funds (listed in the privacy policy), plus a count of all other sites. If we supplied a staff list: whether the address is on it. |
| What is not included? | Passwords, password hashes, and any other value that was exposed. The service does not receive or store them. The names of other websites found in malware logs are discarded and never stored. |
| Where does it come from? | Have I Been Pwned. It is not collected from the person. |
| Who sees it? | **[YOU: roles in your organisation with access to the account, by role, not by name. Today an account has one user.]** Lists mask addresses. Full detail is shown one finding at a time, and each view is recorded. |
| How long is it kept? | Stored scans: 90 days, and the latest scan of the domain for longer. The period is one setting for the whole service. We cannot change it. A finding that has been resolved for longer than that period is deleted. A finding that is still open is kept while it stays open. Everything is deleted when we delete the domain. |
| How is it protected? | Findings are encrypted in the service's database. Findings that name a person are produced only while our domain is verified. Reports are downloaded with addresses masked unless we ask for them to be shown. Alerts never name a person, an address or a breach. The service has not had an independent security review, and no backups of it are taken yet. |
| Where is it kept? | In Germany, on one server at Hetzner Online GmbH. The privacy policy lists the other companies involved. |
| Do we supply a staff list? | **[YOU: yes or no. If yes, who is on it and where it comes from.]** With a list, each finding says whether the address belongs to current staff. Today a list can be loaded with the command-line tool only. |

## Part 1: purpose test

### 1.1 What are we trying to achieve?

**[YOU: write your purpose in one or two sentences. Example wording follows. Change it to fit.]**

> Example: We want to know when a work account is at higher risk of being taken over because its address, and possibly its password, was exposed in a breach elsewhere. When we know, we reset the password, check that multi-factor authentication is on, and look for signs of misuse.

### 1.2 Why does it matter to us?

Tick what applies and add detail.

- [ ] Our staff have access to funds, signing keys or production systems. **[YOU: detail]**
- [ ] Reused passwords and stolen session data are a common way into organisations like ours. **[YOU: any incident or near miss of your own]**
- [ ] We have a legal or contractual duty to secure our systems. **[YOU: which duty]**
- [ ] A takeover of a staff account could harm our users or customers. **[YOU: how]**
- [ ] Other: **[YOU]**

### 1.3 Who benefits?

| Who | Benefit |
|---|---|
| The organisation | **[YOU]** |
| The member of staff | They learn that an account of theirs was exposed and can protect themselves. |
| Our users and customers | **[YOU]** |
| The public | **[YOU, or "none claimed"]** |

### 1.4 Is the purpose lawful and recognised?

Recital 49 of the GDPR says that processing personal data to the extent strictly necessary and proportionate for ensuring network and information security constitutes a legitimate interest of the controller.

**[YOU: note any law, regulator's guidance or industry rule in your country that supports or limits this.]**

### 1.5 Result of the purpose test

**[YOU: "We have a legitimate interest", or "We do not". One sentence of reasoning.]**

## Part 2: necessity test

### 2.1 Does the processing actually help?

**[YOU: describe what you will do when a finding appears. If you would do nothing with a finding, the processing does not help and you should not do it.]**

| Finding | Our action | Who acts | Within |
|---|---|---|---|
| Address in a breach that contained passwords | **[YOU]** | **[YOU]** | **[YOU]** |
| Address in a breach with no passwords | **[YOU]** | **[YOU]** | **[YOU]** |
| Address in a malware log | **[YOU]** | **[YOU]** | **[YOU]** |
| Address of a person who has left | **[YOU]** | **[YOU]** | **[YOU]** |

### 2.2 Could we achieve the purpose with less data, or none?

Consider each alternative honestly.

| Alternative | Would it achieve the purpose? | Why we do or do not use it instead |
|---|---|---|
| Ask each person to check their own address and tell us | **[YOU]** | **[YOU]** |
| Enforce multi-factor authentication everywhere and ignore breaches | **[YOU]** | **[YOU]** |
| Look at counts only, without addresses | **[YOU]** | **[YOU]** |
| Look at breach findings but not malware log findings | **[YOU]** | **[YOU]** |
| Force a password reset for everyone on a schedule | **[YOU]** | **[YOU]** |

### 2.3 Is each item of data needed?

| Item | Needed? | Why |
|---|---|---|
| The address | **[YOU]** | Without it we cannot tell whose account to protect. |
| Breach name and date | **[YOU]** | **[YOU]** |
| Kinds of data in the breach | **[YOU]** | Tells us whether a password was exposed, which decides how urgent it is. |
| Names of our own systems and of high-value services from malware logs | **[YOU]** | Tells us which logins to reset first. |
| Count of other sites from malware logs | **[YOU]** | **[YOU]** |
| Whether the address is on our staff list | **[YOU]** | Lets us tell current staff from former staff and shared mailboxes. |

### 2.4 Result of the necessity test

**[YOU: "The processing is necessary", "It is necessary only in part", or "It is not necessary". If in part, say what you will leave out.]**

## Part 3: balancing test

### 3.1 What would people expect?

| Question | Answer |
|---|---|
| Is the address a work address that we issued? | Yes. The service rejects supplied addresses at other domains, and the breach search returns only addresses at our domain. |
| Have we told staff that we do this? | **[YOU: yes or no. Where: contract, staff handbook, security policy, privacy notice.]** |
| Would a reasonable member of staff be surprised? | **[YOU]** |
| Were former staff told, before they left, that checks continue? | **[YOU]** |
| Do staff use work addresses for personal accounts? Is that allowed by our policy? | **[YOU]** |

### 3.2 What is the relationship?

We are the employer or the engaging organisation. There is an imbalance of power. Staff cannot easily refuse. This weighs against us and means the safeguards in 3.5 matter more.

**[YOU: note whether staff representatives, a works council or a union must be informed or consulted under your national law. If so, record when that was done.]**

### 3.3 What could go wrong for the person?

| Risk | How likely | How serious | Notes |
|---|---|---|---|
| The person is blamed or disciplined for being the victim of a breach | **[YOU]** | **[YOU]** | The service's terms forbid using findings this way. |
| The name of a breach reveals that the person used a work address on a personal site. The name of a site can reveal health, beliefs, sexual life or political views. | **[YOU]** | **[YOU]** | The service stores and shows breach names in full and does not filter them. Limit who may open findings. |
| A malware log finding shows that the person had a login at a service they also use privately, such as Google, Discord or Telegram | **[YOU]** | **[YOU]** | Names of sites outside our own systems and the fixed list are not stored, only counted. |
| A finding suggests that the person's own device was infected, which may be a personal device | **[YOU]** | **[YOU]** | **[YOU: how you will approach the person]** |
| The findings are seen by more people than needed | **[YOU]** | **[YOU]** | Lists and default reports are masked. Each view of a finding about a person is recorded in the audit log, which the account owner can read. |
| The findings are themselves leaked | **[YOU]** | **[YOU]** | Findings are encrypted in the service. No passwords are held, which limits the harm. |
| A finding is wrong or out of date | **[YOU]** | **[YOU]** | The finding shows that an address was in a breach, not that the account is compromised now. |
| Former staff are affected without knowing | **[YOU]** | **[YOU]** | **[YOU]** |

### 3.4 Are any of the people in a vulnerable position?

**[YOU: for example people under 18, or people in a country where a revealed site could put them in danger.]**

### 3.5 Safeguards

Tick those you apply. An unticked box is a gap to explain or close.

Provided by the service:

- [x] No passwords or breached values are received or stored.
- [x] Findings about a person are produced only for a domain we have verified.
- [x] Findings are encrypted in the service's database.
- [x] Lists and default reports mask addresses. Opening a finding about a person is recorded.
- [x] Names of websites from malware logs are kept only for our own systems and a fixed list of high-value services.
- [x] Alerts do not name people, addresses or breaches.
- [x] Findings are shown to us only, and are not published.
- [x] No profile or score of a person is produced.

Applied by us:

- [ ] Staff have been told in writing, before the first scan. **[YOU: where]**
- [ ] Access to findings is limited to **[YOU: roles]**.
- [ ] We have a written rule that nobody is disciplined for appearing in a breach.
- [ ] We tell the person concerned about each finding, privately, with advice on what to do.
- [ ] We have decided who may open findings about people. **[YOU: decision]**
- [ ] We remove people who have left from any staff list we supply.
- [ ] We have checked the service's retention period and it suits us.
- [ ] We read the audit log at regular intervals to see who opened findings about people.
- [ ] We have chosen alert channels that only the right people can read.
- [ ] We use masked reports whenever a report leaves the security team.
- [ ] We have a way for staff to object, described in 3.6.

### 3.6 The right to object

A person can object to processing based on legitimate interests (GDPR Article 21). We must then stop, unless we can show compelling legitimate grounds that override their interests.

| Question | Answer |
|---|---|
| How does a person object? | **[YOU: contact address or process]** |
| Who decides? | **[YOU: role]** |
| How can we act on it? | The service cannot yet exclude one address from a scan, or delete the records about one person. Our options are to delete the domain, to remove the DNS record, which stops scans and withholds the stored findings about people from view (they are deleted only when the domain is deleted), or to continue and record our compelling grounds. **[YOU: which, and why]** |

### 3.7 Result of the balancing test

**[YOU: weigh what you found. State plainly whether the interests of the people concerned override yours. If the balance is close, say what further safeguard tips it, and put that safeguard in place before you start.]**

## Decision

| | |
|---|---|
| Can we rely on legitimate interests for this processing? | **[YOU: yes, yes with conditions, or no]** |
| Conditions | **[YOU]** |
| Parts of the processing we will not do | **[YOU]** |
| Do we need a data protection impact assessment as well? | **[YOU: yes or no, with reason]** |
| Has our privacy notice to staff been updated? | **[YOU: yes, with date, or the date by which it will be]** |

## When to review

Review this assessment:

- at the date set at the top;
- when the service adds a new source or stores a new kind of data;
- when you change who has access;
- after any objection or complaint;
- after any incident involving the findings.

## Record of changes

| Date | Change | By |
|---|---|---|
| **[YOU]** | First version | **[YOU]** |
