> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Data processing agreement: outline

Status: outline for the hosted service, which has been built but is not yet deployed. This is a list of what the agreement must cover under GDPR Article 28, with the facts filled in from how the software behaves. It is not yet contract wording. **[LAWYER: draft the clauses.]**

## Parties

| Role | Party |
|---|---|
| Controller | The customer organisation named in the account |
| Processor | **[TO DECIDE: legal name of the operating entity]**, **[TO DECIDE: registered address]** |

A **controller** decides why and how personal data is used. A **processor** handles the data for the controller, on its instructions. A **data subject** is the person the data is about.

**[LAWYER: confirm that the operator is a processor and not a joint controller. See README open question 1.]**

## 1. Subject matter and duration

- **Subject matter:** scanning the public exposure of the controller's verified domain and reporting findings and changes to the controller.
- **Duration:** from the date the controller accepts the terms of service until its account is closed and its data is deleted under section 11.

## 2. Nature and purpose of the processing

- **Nature:** collection from the sources listed in the [privacy policy](privacy-policy.md), storage, comparison between scans, display to the controller, generation of reports, deletion.
- **Purpose:** network and information security of the controller. The controller learns which work accounts and systems are exposed so that it can protect them.
- The processor does not use the data for any purpose of its own. It does not combine one customer's data with another's.

## 3. Types of personal data

| Type | Detail |
|---|---|
| Work email addresses | Found in breach data, or uploaded by the controller |
| Breach exposure | Breach name, breach date, kinds of data the breach contained |
| Malware log exposure | Names of websites that captured logins were for, only where the site is the controller's own or is on a fixed list of services that control code, infrastructure or funds. A count of all other sites. |
| Staff list membership | Whether an address in a finding is on the staff list the controller supplied |
| Blockchain addresses | Owner addresses of a Safe multisig wallet named by the controller |
| Code locations | Repository, file, line, commit and date where a credential was found |
| Account users | Email address, role, time of last sign-in. The email address of the user who requested each scan is stored with the scan. |

Not processed: passwords, password hashes, any value exposed in a breach, the content of found credentials beyond the first four characters and a short hash, committer email addresses.

**Special categories of data:** none are collected on purpose. The names of websites outside the two kinds above are discarded during the scan and never stored. The name of a breach is stored in full and could reveal such data. **[LAWYER: see README open question 3.]**

## 4. Categories of data subject

- Current staff and contractors of the controller who hold an email address at the verified domain.
- Former staff whose address at the verified domain appears in breach data.
- Holders of shared or role addresses at the verified domain.
- Holders of the blockchain addresses that own the controller's multisig wallet.
- People who use the controller's account.

## 5. Documented instructions

5.1 The processor processes personal data only on the controller's documented instructions.

5.2 The instructions are: the terms of service, this agreement, and the choices the controller makes in the service. Those choices are:

- which domains to add;
- which scan depth to use, and how often scheduled scans run;
- whether to supply a GitHub organisation, a wallet address, a job board or a staff list;
- which alert channels to set up;
- when to delete a domain.

The retention period is one setting for the whole service. **[TO DECIDE: whether each controller can set its own.]**

5.3 The processor tells the controller if it believes an instruction breaks data protection law.

5.4 If a law requires the processor to process the data in another way, the processor tells the controller first, unless that law forbids it.

## 6. Confidentiality

6.1 Everyone the processor authorises to handle the data is bound by a duty of confidentiality.

6.2 Access by the processor's staff is limited to what is needed to run and support the service. **[TO DECIDE: access rules and who holds the encryption keys.]**

6.3 Within the controller's account, roles exist: owner, member and viewer. A viewer can read but not change. Only an owner can read the audit log. **[NOT YET BUILT: inviting further users. Today each account has one user, the owner.]**

## 7. Security measures

The processor applies the measures in Annex A. It may change them if the level of protection does not fall.

## 8. Sub-processors

8.1 The controller gives general authorisation for the sub-processors listed in Annex B.

8.2 The processor tells the controller at least **[TO DECIDE: notice period]** before adding or replacing a sub-processor. The controller may object. If the objection cannot be resolved, the controller may close its account.

8.3 The processor puts the same data protection duties on each sub-processor by contract.

8.4 The processor remains responsible to the controller for what a sub-processor does.

**[LAWYER: decide which third-party sources are sub-processors and which are independent sources. Have I Been Pwned receives only the domain name and returns data. See README open question 8.]**

8.5 Alert providers. If the controller sets up an alert channel, the text of alerts is sent to the provider of that channel: Slack, Discord, Telegram, or the email provider of the address named. The controller chooses the channel and supplies its credentials. Alert text never holds a person's name or address, a credential or the name of a breach. **[LAWYER: sub-processor, or recipient chosen by the controller. See README open question 34.]**

## 9. Transfers outside the EEA or UK

9.1 Data is stored in **[TO DECIDE: storage region or regions]**.

9.2 The processor transfers personal data to another country only on the controller's documented instructions and with a transfer tool that the law accepts.

9.3 Transfer tool for each sub-processor: **[TO DECIDE, once providers are chosen]**.

## 10. Help with data subject requests

10.1 If a data subject writes to the processor, the processor passes the request to the controller without delay and does not answer it itself, unless the controller asks it to.

10.2 The service gives the controller these means to answer requests:

| Request | What the controller can do in the service |
|---|---|
| Access | Download a report in JSON or HTML for a scan, with personal details shown. Findings about the person can be found in it by address. **[NOT YET BUILT: export of all data about one person.]** |
| Erasure | Delete the domain, which deletes all scans and findings for it. **[NOT YET BUILT: deleting the findings about one person only.]** |
| Objection or restriction | Stop running breach checks for the domain. **[NOT YET BUILT: excluding one address from future scans.]** |
| Rectification | Findings are copies of facts from public sources. They cannot be edited. A finding that is wrong at the source must be corrected at the source. |

10.3 The processor also helps the controller with security of processing, breach notification, impact assessments and prior consultation (GDPR Articles 32 to 36), taking into account the information the processor has.

## 11. Personal data breach

11.1 The processor tells the controller without undue delay after becoming aware of a personal data breach that affects the controller's data, and in any case within **[TO DECIDE: period, for example 48 hours]**.

11.2 The notice says, as far as known: what happened, which data and roughly how many people are affected, the likely effects, and what has been done.

11.3 The notice goes to the email address of the account's owner. **[NOT YET BUILT: a separate security contact.]**

## 12. Deletion or return

12.1 When the agreement ends, the controller chooses deletion or return.

12.2 **Return:** reports per scan, in JSON or HTML. **[NOT YET BUILT: a full export.]**

12.3 **Deletion:** deleting a domain removes the domain record, staff list, verification record, scans, findings and finding history, at once. **[NOT YET BUILT: deleting an account or an organisation. Until it is built, the processor does this by hand on request.]**

12.4 Backups are deleted within **[TO DECIDE: backup retention period]**.

12.5 Audit log entries are kept for **[TO DECIDE: audit log retention period]**. **[LAWYER: see README open question 25.]**

12.6 The [data retention policy](data-retention-policy.md) has the detail.

## 13. Audits and information

13.1 The processor gives the controller the information needed to show that Article 28 is met.

13.2 The software is open source. The controller may inspect the code that performs the processing.

13.3 The owner of the controller's account can read the last 300 entries of the audit log for that account.

13.3a The service has not had an independent security review. **[TO DECIDE: when one will be done, and whether its result is shared with controllers.]**

13.4 The processor allows audits by the controller or an auditor it appoints. **[TO DECIDE: notice, frequency, cost and confidentiality conditions.]**

## 14. Liability

As in the terms of service. **[LAWYER: confirm interaction with GDPR Article 82.]**

---

## Annex A: security measures

This annex describes what the software does today.

### A.1 Encryption

| Measure | Detail |
|---|---|
| Encryption of stored findings | The body of every finding is encrypted in the database with Fernet (AES in CBC mode with a 128-bit key, and HMAC-SHA256 for integrity). |
| Encryption of staff addresses | The uploaded staff list is encrypted the same way. |
| Encryption of verification tokens | Encrypted the same way. |
| Encryption of alert channel settings | Webhook addresses and bot tokens are encrypted the same way. They are never shown back in the service. |
| One set of keys | The same keys protect all customers' data. **[NOT YET BUILT: keys per organisation.]** |
| Key supply | Keys are read from the environment variable `PW_DATA_KEYS`. They are never read from a settings file. Outside development mode the service refuses to start without them. |
| Key rotation | Several keys can be supplied, newest first. New data is encrypted with the newest key. Older data can still be read and can be re-encrypted. |
| Matching without exposing | Findings about a person are matched between scans by a keyed hash (HMAC-SHA256) of the address. |
| What is not field-encrypted | Hostnames, IP addresses, DNS records, blockchain addresses, scan metadata, the kind and severity of each finding, account users' email addresses, the text of alerts, and the audit log. |
| Encryption in transit | The bundled proxy obtains a TLS certificate automatically. Outside development mode the service refuses to start unless its public address is HTTPS, and it sends a Strict-Transport-Security header. Email is sent with STARTTLS. Alert webhooks are HTTPS only. |
| Encryption of the disk and backups | **[TO DECIDE: depends on hosting provider.]** |

### A.2 Data minimisation

| Measure | Detail |
|---|---|
| No breached values | The data model has no field for a password, a hash or any breached value. |
| Credentials in code | Only the type, location, first four characters and a short hash (first 8 hexadecimal characters of SHA-256) are kept. Credentials of 12 characters or fewer show no characters. |
| Credentials are not tested | The scanner's verification feature is switched off. |
| Committer addresses | Discarded. |
| Staff list validation | Addresses at a domain other than the customer's are rejected. |
| Staff list kept out of results | The staff list is removed from scan snapshots and reports. |
| Temporary files | Downloaded repositories and tool files are held in a temporary directory that only the service can read. It is deleted when the scan ends. |
| Masked lists | Lists and scan pages mask names and addresses of people. Detail is shown one finding at a time. |
| Masked reports | Reports are downloaded with addresses masked unless the user asks for them to be shown. |
| Malware log sites | Names of sites are kept only for the controller's own systems and a fixed list of 19 services. Others are counted and discarded. |
| Alerts | Alert text names no person, address, credential or breach. |

### A.3 Separation between customers

| Measure | Detail |
|---|---|
| Tenant identifier | Every table that holds customer data carries a tenant identifier. |
| Single query path | All reads and writes of customer data go through one component that limits each query to one tenant. One exception exists: the code that withdraws other organisations' verification of a domain when a new organisation proves control. It changes verification standing and nothing else. |
| Tenant from the session | The web service takes the tenant from the signed-in session, never from the address or a form. An object that belongs to another tenant is reported as not found. |
| Database row-level security | **[NOT YET BUILT.]** Separation is enforced in the application only. |
| Shared cache | A cache of slow public sources, such as the public catalogue of breaches, is shared. It holds no customer data. |

### A.4 Access control and consent

| Measure | Detail |
|---|---|
| Domain verification | DNS TXT record, accepted only from the domain's authoritative nameservers or from at least two independent public resolvers. |
| Re-check | Verification is checked again before every scan, and once a day. After three failed checks in a row it is withdrawn. |
| One holder | Only one organisation at a time holds verification of a domain. |
| Proof accepted | The hosted service accepts a DNS record only. A typed statement of authority, which the command-line tool accepts, is ignored. |
| Per-person data | Produced only for a verified domain. This is enforced in two places in the code. Stored findings about people cannot be opened, and reports cannot be downloaded with personal details shown, unless the domain is currently verified. **[NOT YET BUILT: deleting them when verification is lost.]** |
| Active checks | Refused without authorisation. There is no override setting. |
| Sign-in | By emailed link. No passwords exist. A link works once and expires after 15 minutes. Opening the link shows a button, and the link is used only when the button is pressed. Link tokens and session cookies are stored only as hashes. |
| Sessions | End after 12 hours without use, or after 7 days. |
| Sign-in limits | At most 5 links per email address and 20 per network address in an hour. The sign-in page gives the same answer whether or not an account exists. |
| Roles | Owner, member, viewer. Membership is checked on every request. |
| Forged requests | Every form carries an anti-forgery token. |
| Web pages | No JavaScript. The content security policy forbids scripts and all third-party resources. |

### A.5 Limits on scanning

| Measure | Detail |
|---|---|
| Scope | Only hosts under the verified domain are contacted. |
| Private addresses | A host is not contacted if any address it resolves to is private, reserved, loopback, link-local, multicast, carrier-grade NAT or a cloud metadata address. |
| Do-not-contact list | A host is not contacted if its name, or any address it resolves to, is on the operator's do-not-contact list. This applies to every check that contacts hosts: the web probe, the TLS handshake, the MTA-STS policy request, the port check and the exposure checks. |
| Verification before any scan | The hosted service scans a domain only once control of it is proved, at every depth. Checked at request, by the scheduler, and when the scan starts. |
| Passive depth | Makes no connection to the controller's hosts. |
| Frequency | A scan of a domain can be requested at most once every six hours. |
| Network placement | In the bundled deployment, only the worker can reach scanned hosts, and the database has no route to the internet. |
| Second check | The address a tool reports it connected to is checked again, and the result is discarded if that address is not public. |
| Limits per scan | At most 500 hosts are contacted and at most 200 addresses are port-checked. |
| Rate | Requests are rate-limited. See the [scanning authorisation and acceptable use policy](scanning-authorisation-and-aup.md). |
| Exposure checks | Each check template is read before use. It is admitted only if every request is a plain GET or HEAD with no body or payload, stays on the scanned host, and makes at most six requests. |
| Redirects | Not followed. |

### A.6 Logging and accountability

| Measure | Detail |
|---|---|
| Audit log | Records sign-in and sign-out, scans requested and completed, reports downloaded, verification started, checked, withdrawn and superseded, domains added, changed and removed, changes to a finding's status, and alert channels added, tested and removed. |
| Views of sensitive findings | Opening a finding about a person or a credential is recorded with the user and the kind of finding, not the name of the person it is about. Downloading a report is recorded with whether personal details were shown. |
| Retention runs | Each run is recorded, whether started by the worker or by the command-line tool. |
| Append-only | The software has no page or function that changes or deletes an audit entry. **[NOT YET BUILT: enforcement at database level.]** |
| Secret scrubbing | Known secrets and common token formats are removed from log output. |

### A.7 Operations

| Measure | Detail |
|---|---|
| Secrets | API keys are read from the environment only. A settings file that contains something that looks like a secret is refused. |
| External tools | Run with a minimal environment built from an allowlist, in a temporary home directory, with output size limits and timeouts. |
| Tool versions | The version of each external tool is recorded with each scan. |
| Tool integrity | Scanning tools are pinned to versions and checked against checksums. |
| Independent security review | None has been done. |
| Backups, monitoring, patching, staff training, incident response | **[TO DECIDE.]** `docs/operations.md` has an outline. |

## Annex B: sub-processors

| Role | Company | Location | Data | Transfer tool |
|---|---|---|---|---|
| Hosting | **[TO DECIDE]** | **[TO DECIDE]** | All stored data | **[TO DECIDE]** |
| Email (SMTP) | **[TO DECIDE]** | **[TO DECIDE]** | Account users' addresses, sign-in links, text of email alerts | **[TO DECIDE]** |
| Ethereum RPC | **[TO DECIDE]** | **[TO DECIDE]** | Wallet addresses being read | **[TO DECIDE]** |

Alert providers, used only if the controller sets up a channel of that kind:

| Provider | Data | Transfer tool |
|---|---|---|
| Slack | Text of alerts | **[TO DECIDE]** |
| Discord | Text of alerts | **[TO DECIDE]** |
| Telegram | Text of alerts, chat number | **[TO DECIDE]** |
