> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Terms of service

Status: draft, published for review. The hosted service has been live in beta at https://perimeterwatch.org since 30 September 2026. It is free, and sign-up is open. No lawyer has reviewed these terms, and the service has had no independent security review. The legal documents are drafts under review and are not yet in force. These terms do not apply to the open-source command-line tool, which is licensed separately under Apache-2.0.

Last updated: 30 September 2026

Open points are marked in the text. "README open question" followed by a number refers to the [list of open questions](https://github.com/erik1o6/perimeterwatch/blob/main/docs/legal/README.md) in the repository.

## 1. Who we are

There is no legal entity yet. The service is operated by its maintainer, known publicly as code2142, as an individual, while a non-profit entity is being set up. **[TO DECIDE: legal name and legal form of the entity, once established]** Where the entity will be established is not yet known. **[TO DECIDE: jurisdiction]** No registered address exists yet. **[TO DECIDE: registered address]**

In these terms:

- **"We"** and **"the operator"** mean whoever operates the service: today the maintainer, and later that entity.
- **"The service"** means the hosted Perimeterwatch service at https://perimeterwatch.org.
- **"You"** and **"the customer"** mean the organisation that opens an account.
- **"Your domain"** means a domain name you add to the service.
- **"Verified"** means you have proved control of the domain in the way described in section 4.
- **"Scan"** means one run of the service's checks against your domain.
- **"Findings"** means the results of a scan.

## 2. What the service does

You name a domain. The service maps what an outsider can see about the systems behind that domain. It then reports what changed between one scan and the next.

The service has three depths. You choose the depth for each scan.

| Depth | What happens |
|---|---|
| Passive | The service reads public records and third-party indexes. It makes no connection to your hosts. The only question sent to your nameservers is the check of the verification record in section 4. |
| Probe | Everything in passive. The service also sends one ordinary web request and one TLS handshake on port 443 to each host found under your domain. From hosts that answer as web servers it reads the front page and the script files that host serves. From your domain it reads the security.txt file, and the MTA-STS policy file if you publish one. It asks each of your domain's nameservers a few ordinary DNS questions. |
| Active | Everything in probe. The service also checks which of the 100 most common ports accept a connection, and sends read-only requests that look for known exposures. It makes repeated TLS handshakes to see which versions and cipher suites a host accepts. It reads what your SSH servers offer, without signing in. It asks each nameserver once for a zone transfer. If one of your DNS names points at a storage bucket, it asks the storage provider what an anonymous visitor may do with that bucket. |

The full description is in the [scanning authorisation and acceptable use policy](scanning-authorisation-and-aup.md). That policy is part of these terms.

The service does not:

- scrape LinkedIn or social media;
- build profiles of individual people;
- hold passwords, password hashes or any other value taken from a data breach;
- test whether a credential it finds still works;
- attempt to exploit anything;
- produce an overall score or rating;
- publish findings. Findings are shown only to the customer that verified the domain.

## 3. Who may use the service

3.1 The service is for organisations, not for individuals acting for themselves. It is built for organisations working with crypto-assets and web3 technology.

3.2 The person who opens the account must have authority to bind the organisation to these terms. **[LAWYER: how this works for an organisation with no legal personality.]**

3.2a An account is opened by signing in with a work email address. We send a link to that address. There is no password. Each new account gets its own organisation in the service. Every page of the service links to these terms in its footer. **[NOT YET BUILT: asking a new user to accept these terms at sign-in, and recording that they were accepted. See README open questions 32 and 33.]**

3.2b You may add up to 10 domains.

3.3 You may not use the service if the law that applies to you or to us forbids us to provide it to you. **[LAWYER: sanctions and export control wording.]**

3.4 We may decline any application.

## 4. Verifying your domain

4.1 To verify a domain, you create a DNS TXT record at `_perimeterwatch-verify.<your domain>` with the value `pw-verify=<token>`. We give you the token.

4.2 We accept the record only if the answer comes from the domain's own authoritative nameservers, or if at least two independent public DNS resolvers return it.

4.3 We check the record again before every scan, and once a day. If the record is missing when a scan starts, the scan does not run.

4.4 Removing the record withdraws your authorisation. After three failed checks in a row your verification is withdrawn, and we tell you through your alert channels. If you have set up no alert channel, no message is sent, and you see the change on the domain's page.

4.4a Only one organisation at a time can hold verification for a domain. If another organisation proves control of your domain, your verification is withdrawn and we tell you through your alert channels. If you have set up no alert channel, no message is sent, and you see the change on the domain's page. **[LAWYER: dispute process. See README open question 31.]**

4.4b The hosted service accepts a DNS record as the only proof of control.

4.5 These need a verified domain:

- any scan, at any depth;
- any finding that names an individual email address, including opening one that was stored earlier.

4.5a The service scans a domain only once it is verified. This holds for every depth. You can add a domain before it is verified, but it is not scanned. The promises in section 5 apply to every domain you add.

4.6 A domain you add is scanned automatically every 24 hours unless you choose another interval or switch this off. Automatic scans run at probe depth, and only while the domain is verified. Active scans run only when you request one. A scan of the same domain can be requested at most once every six hours.

## 5. Your promises to us

You promise that, for every domain you add and for as long as it stays in your account:

5.1 You own the domain or you are authorised by its owner to have it scanned.

5.2 You have authority to approve security testing of the hosts under the domain, at the depth you select.

5.3 Where a host under your domain runs on infrastructure owned by someone else, such as a cloud provider, a content delivery network or a software-as-a-service provider, you have checked that provider's terms and the scan depth you select is allowed by them. The same applies to the provider that runs your domain's nameservers, and to the provider of any storage bucket your DNS points at.

5.4 Any staff email addresses you upload are work addresses at your own domain, belonging to people who work for you.

5.5 You have a lawful basis to process data about your staff's exposure in data breaches, and you have told your staff about it as the law requires.

5.6 The information you give us about your organisation is true.

You must tell us promptly if any of these stops being true.

## 6. Acceptable use

You must follow the [scanning authorisation and acceptable use policy](scanning-authorisation-and-aup.md). In particular, you must not:

- add a domain you are not authorised to have scanned;
- use findings to attack, harass or discriminate against any person;
- use breach findings to discipline staff for having been the victim of a breach;
- try to obtain findings about an organisation other than your own;
- resell findings or use the service to build a breach search service;
- interfere with the service or try to get around its limits.

## 7. Your data and personal data

7.1 Your findings belong to you.

7.2 Some findings contain personal data about your staff. For that data you are the controller and we are your processor. The [data processing agreement](dpa-outline.md) applies and is part of these terms. **[LAWYER: confirm roles, see README open question 1.]**

7.3 The [privacy policy](privacy-policy.md) explains what we handle and why.

7.4 The [data retention policy](data-retention-policy.md) explains how long we keep data and how it is deleted.

7.5 Lists in the service mask the names and addresses of people. Details are shown one finding at a time. Each time a user opens a finding about a person or a credential, or downloads a report, the service records who did so in the audit log. The owner of the organisation's account can read that log.

7.6 Alerts. You may have alerts sent to an email address, a Slack or Discord webhook, or a Telegram bot. You choose the channel and you are responsible for who can read it. Alert text holds your domain name, the titles of findings that are not about a person or a credential, counts, and a link. It never holds a person's name or address, a credential or the name of a breach.

7.7 No backups are taken of the service's data yet. If the server is lost, your stored scans and findings are lost with it. Download the reports you need to keep.

## 8. Third-party data

8.1 The breach exposure check is switched off in the hosted service today. No breach data source is configured. If it is switched on, breach data will come from Have I Been Pwned and is licensed under the Creative Commons Attribution 4.0 International licence. Wherever you show or share that data, you must keep the attribution that appears in our reports.

8.2 You may not use breach findings to offer a breach search service to anyone.

8.3 Other findings rely on public sources that we do not control. They may be incomplete, late or wrong.

## 9. Price

The service is provided without charge. The service's home page says that it is free and stays free. **[TO DECIDE: whether any cost recovery or donation model will apply, once the entity exists]**

## 10. No warranty

10.1 The service is provided as it is and as it is available. It is in beta.

10.2 A scan shows what could be seen from outside at the time of the scan, using the sources and checks the service has. It is not a penetration test, an audit or a certification.

10.3 A scan with no findings does not mean your systems are secure. A finding does not always mean there is a real problem.

10.4 Credentials found in public code are not tested. Some will already be revoked, and some will be examples.

10.5 We do not promise that the service will be available without interruption, or that any third-party source will be available.

10.6 To the extent the law allows, we exclude all warranties that are not written in these terms. **[LAWYER: adapt to governing law.]**

## 11. Limits of liability

11.1 Nothing in these terms limits liability that cannot be limited by law.

11.2 Subject to 11.1, we are not liable for:

- loss of profit, revenue, business or data;
- indirect or consequential loss;
- loss caused by your reliance on a finding or on the absence of a finding;
- loss caused by a scan you requested of a host you were not authorised to have scanned.

11.3 Subject to 11.1, our total liability to you in any twelve months is limited to an amount that has not been set. **[TO DECIDE: liability cap amount, once the entity and the governing law are known]**

11.4 You will cover our reasonable losses and costs if a third party brings a claim against us because a promise you made in section 5 was untrue. **[LAWYER: indemnity wording and whether it is appropriate.]**

## 12. Suspension

We may suspend scans of a domain, or your whole account, without notice if:

- we receive a credible complaint that you are not authorised to have a domain scanned;
- the operator of a host asks us to stop contacting it, under the [opt-out policy](opt-out.md);
- we believe you have broken section 5 or section 6;
- a third-party source requires us to stop;
- we need to protect the service or other people.

We will tell you what we did and why, unless the law forbids it.

## 13. Ending the agreement

13.1 You may delete a domain at any time in the service. You may close your account at any time by writing to support@perimeterwatch.org from the account's address. We then close it by hand, within 30 days. **[NOT YET BUILT: closing an account in the service.]**

13.2 We may end the agreement by giving you 30 days' notice.

13.3 We may end the agreement at once if you seriously break these terms.

13.4 When the agreement ends we delete your data as set out in the [data retention policy](data-retention-policy.md).

13.5 Sections 8, 10, 11 and 15 continue after the agreement ends.

## 14. Changes

14.1 We may change the service. We will not add a new kind of check that contacts your systems at a depth you have not selected.

14.2 We may change these terms. We will give you 30 days' notice of a change that reduces your rights, by email to the address of your account. If you do not agree, you may close your account before the change takes effect.

14.3 We will keep a list of sub-processors and tell you at least 30 days before adding one. See the [data processing agreement](dpa-outline.md).

## 15. Law and disputes

15.1 The law that governs these terms has not been chosen. It depends on where the entity is established. **[TO DECIDE: governing law]**

15.2 The courts or arbitration body that will decide disputes have not been chosen. **[TO DECIDE: courts or arbitration body, and seat]**

## 16. Contact

| Purpose | Address |
|---|---|
| Legal notices | legal@perimeterwatch.org |
| Support | support@perimeterwatch.org |
| Privacy | privacy@perimeterwatch.org |
| Abuse reports | abuse@perimeterwatch.org |
| Security reports | security@perimeterwatch.org |
| Anything else | hello@perimeterwatch.org |
