> Draft for review and editing. Not yet submitted.

# Team

TheDAO Fund gives a grant, as opposed to an RFP, to a named team "because that team already has a head start on the work", and asks for "a thorough justification of why this team is the one to deliver". This file makes that case. Most of it can only be written by the maintainer.

## The head start

This part is factual and can be checked in the repository.

- The scanning engine is written and works. It has 34 check modules and 104 kinds of finding.
- The web service and its worker are written, tested, and live in beta at https://perimeterwatch.org since 30 September 2026: sign-in by emailed link, separation of organisations, domain verification, scheduled scans, alerts by email and chat, an audit log, and automatic deletion of old data.
- 2,555 automated tests pass in public CI on every change. Four test files cover the safety rules of the engine: authorisation, domain validation, the guard against contacting private addresses, and the handling of external tools. One test file tries every route of the web service as a different organisation.
- Deployment files, a CI workflow, a licence file, a security policy and draft legal documents are written. The legal drafts are published at https://perimeterwatch.org/legal and marked as drafts.
- The design decisions that take longest to get right are already made and implemented: the consent model, the rule that a secret is never stored, the rule that lookalike domains are never contacted, the filter that admits only read-only exposure checks, and the rule that a finding is not marked as fixed when its check did not run.
- The report format has a JSON schema, so other tools can read it.

The limits of the head start are as plain as the head start. The code was published on 29 September 2026. The web service went live in beta on 30 September 2026, on one server, and monitors only the maintainer's own domains. The CI workflow runs in public on every change and passes: tests on Python 3.13 and 3.14, tests against Postgres, a dependency audit and a build of the container image. Nobody outside the team has reviewed the code, no lawyer has reviewed the legal drafts, and no outside organisation relies on the service.

A team chosen through an RFP would start by making these decisions and writing this software. This team starts from software that is published and running, and goes straight to review, hardening and onboarding.

Repository: https://github.com/erik1o6/perimeterwatch
Sample report: https://github.com/erik1o6/perimeterwatch/tree/main/docs/sample-report
Live beta: https://perimeterwatch.org
Date work began: **[TODO]**

## code2142, author and maintainer

code2142 is a security lead with more than ten years of experience, the last several spent running security for crypto organisations. They have been head of security at a DeFi lending protocol and at three other companies, and now advise a second DeFi organisation on its security programme. Before that they worked as a penetration tester and as a Linux kernel developer. They hold the Offensive Security Certified Professional (OSCP) certification and an ETHSecurity Badge from TheDAO Security Fund.

code2142 submits under a pseudonym. The fund's curators can be given the maintainer's identity privately on request. **[TODO: confirm you are willing to offer this, or delete the two sentences.]**

### Prior work

Described without names, to keep the pseudonym. Each item can be evidenced privately.

- Ran the security programme of a DeFi lending protocol: incident response, on-chain monitoring, an emergency pause system, staff device security and access management. This is the same ground Perimeterwatch covers from the outside.
- Organised smart-contract review for that protocol: dozens of reviews by independent firms, a public audit competition, and a bug bounty programme.
- Led incident response for attacks aimed at executives, including analysis of the malware used.
- Led ISO 27001 and SOC 2 certification work at three companies, and served as data protection officer under GDPR at two.
- Wrote an open-source tool that checks deployed contract bytecode against its source.
- Spoke on security panels at several Ethereum conferences between 2024 and 2025.

### Relevant experience for this project

- Running a service that holds sensitive data for other organisations: responsible for security and data protection at companies holding customer data, including as data protection officer.
- Outside-in security assessment: several years of penetration testing of web applications, APIs and client software, for clients in finance and cryptocurrency.
- The Ethereum ecosystem: security lead at DeFi organisations since 2022, and a holder of the ETHSecurity Badge.
- Relationship with the bodies named in `06-positioning.md`: adopted the SEAL Safe Harbor agreement at a previous organisation. **[TODO: add any working relationship with SEAL, OpSec auditing firms or Safe that you are willing to state. Otherwise leave as is.]**

### Public profiles

- GitHub: https://github.com/erik1o6

### Time available

**[TODO: state how many hours per week you can give this project during the grant, and whether you have other commitments in that period.]**

## Second maintainer

A single maintainer is a risk for a service that organisations will depend on. It is listed in `08-risks.md`.

**[TODO: choose one and delete the others.]**

- Option A: "**[name]** will join as second maintainer. **[biography, prior work, link, hours per week]**."
- Option B: "There is no second maintainer today. The grant pays for a developer and part-time operations support, and one of them is given commit and deployment rights during Milestone 1." The submitted milestones do not include this as a payment criterion.
- Option C: "There is no second maintainer. The project reduces the risk by other means: the code is open source, the deployment is documented so that another person could run it, and organisations can export their data and run the command-line tool themselves."

## The entity

The original idea was a non-profit entity that does this work for any project that opts in.

- Legal form and jurisdiction: **[TODO: for example an association, a foundation, or a company limited by guarantee. State whether it exists or is to be formed.]**
- Who receives the grant funds: **[TODO: the entity, or the maintainer personally until the entity exists.]**
- Who owns the code: the code is open source under Apache-2.0, so any organisation can run it regardless of what happens to the entity.

## Pilot organisations and supporters

**[TODO: name any organisation that has agreed to pilot the web service, or has run the command-line tool, and has agreed to be named. If there are none, delete this section. Do not list anyone who has not agreed in writing.]**

## Why not an RFP

A short paragraph for the submission form, if it asks.

> The engine, the consent model, the report format and the web service are built, tested, published and running in beta. What remains is to have it reviewed, harden and operate it, and get organisations to use it. An RFP would ask competing teams to propose building what already exists. A grant with half of the payment held back until adoption is shown puts the risk on the team and not on the fund.

## Notes for the maintainer (delete before submitting)

- The biography and prior work were written from your CV with names, amounts and dates removed. Read them as someone in the field would: a combination of facts can identify you even when no single one does. The items most likely to do so are the open-source bytecode tool, the conference panels and the Safe Harbor adoption. Remove any you are not comfortable with.
- Left out on purpose because they identify you directly: employer names, the size of the audit competition and bounty programme, the live-funds CTFs, patents, your certification number, your university, languages, and links to talks.
- The repository is published under a GitHub account that is tied to you. Anyone who opens the repository link can see that account.
