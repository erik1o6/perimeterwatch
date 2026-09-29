> Draft for review and editing. Not yet submitted.

# Positioning

This file explains how Parapet relates to other work in the same area. In each case the aim is to supply something the other party can use, and to avoid doing their job.

No partnership or endorsement exists with any body named here. **[TODO: if any conversation has taken place, say so in the relevant section, with the other party's permission.]**

## At a glance

| Other work | What they do | What Parapet does | Relation |
|---|---|---|---|
| OPSEC Ratings Coalition (Round Two RFP, $150,000) | Auditing firms agree one public rating standard | Produces facts about one organisation, for that organisation. Publishes no rating. | A data input, with consent |
| Auditware privacy-preserving EDR (Round Two grant, $300,000) | Detects threats on staff devices | Looks at the organisation from outside | Complementary |
| SEAL Certifications | Accredited firms assess an organisation against published controls | Produces reports that can serve as evidence for some controls | Evidence |
| SEAL 911 | Free emergency help during an incident | Points the organisation to it when a finding looks like an incident in progress | Escalation path |
| SEAL-ISAC | Members share threat intelligence | None built | Possible later |
| Commercial monitoring | Similar checks, sold to companies with security budgets | Open source, free to run yourself, and includes crypto-specific checks | Alternative for teams that go without |

## OPSEC Ratings Coalition

The initiative asks for "at least six OpSec auditing firms agreeing on one public rating standard: an L2BEAT for OPSEC".

Parapet publishes no rating, score or grade. The report states this in its own text: it "gives no overall score". This is a design decision and is already built.

The two projects differ in three ways.

| | OPSEC Ratings Coalition | Parapet |
|---|---|---|
| Audience | The public | The organisation itself |
| Output | A rating, comparable across organisations | A list of findings and fixes, private to the organisation |
| Who decides what is good | A coalition of firms | Nobody. The tool reports facts and a default severity for each. |

**How they fit together.** A rating needs evidence. Some of that evidence can be observed from outside: whether email forgery is prevented, whether DNSSEC is on, how many signers a treasury has. Parapet already collects this and writes it as JSON with a published schema. With the organisation's consent, that file can be handed to whoever produces the rating.

**What is built and what is not.** The JSON output and its schema are built. No agreement exists with the coalition, which has not yet been formed. The proposal commits to keeping the schema stable and documented so that a rating body can consume it. It does not commit the coalition to anything.

## Auditware privacy-preserving EDR

EDR stands for endpoint detection and response. It is software on a staff member's laptop that watches for malicious activity. The fund's announcement describes the Auditware initiative as endpoint detection that respects crypto values.

| | Auditware EDR | Parapet |
|---|---|---|
| Where it runs | On staff devices | On a server outside the organisation |
| What it needs from the organisation | Software installed on every device | A domain name and one DNS record |
| What it sees | What happens on the device | What is public |
| What it aims to do | Stop or detect an infection | Show exposure, including signs that an infection has already happened elsewhere |

The two meet at one point. Parapet reports staff addresses that appear in logs from password-stealing malware. Such a log means a device was infected at some time, possibly a personal device that no EDR covers. An organisation that receives this finding has a reason to install device protection.

Parapet asks less of an organisation than device protection does, so an organisation can start with it and add device protection later. Neither replaces the other.

## SEAL Certifications

SEAL (Security Alliance) maintains a certification framework with six modules: Multisig Ops, Treasury Ops, Incident Response, DevOps and Infrastructure, DNS and Registrar, and Identity and Accounts. Accredited firms carry out the assessments. The protocol team gathers evidence that its practices meet the controls. Source: [SEAL Certification Framework](https://frameworks.securityalliance.org/certs/overview/).

### DNS and Registrar module

Source: [SFC: DNS Registrar](https://frameworks.securityalliance.org/certs/sfc-dns-registrar/).

| SEAL control (as summarised on the SEAL page) | What Parapet reports |
|---|---|
| DNS security standards: DNSSEC on critical domains, CAA records | Whether DNSSEC is on. Whether a CAA record exists. |
| Email authentication: SPF, DKIM, DMARC, with MTA-STS where feasible | The state of each, including whether DMARC is set to reject or only to monitor |
| Monitoring for unauthorised changes to DNS records and security settings | Changes in findings between scheduled scans, with an alert. Scheduled scans and alerts are built in the web service, which is not yet deployed. |
| Monitoring certificate records for unauthorised certificates | Hosts that newly appear in certificate records, and certificates issued to lookalike names |

Parapet does not cover the parts of the module about registrar account access, such as multi-factor login at the registrar. Those cannot be seen from outside.

### Identity and Accounts module

The SEAL overview describes this module as covering "organizational account inventory, phishing-resistant MFA, credential management, takeover monitoring". The detailed controls were not checked for this draft. **[TODO: read the module and list the specific controls for which a Parapet report is evidence. Likely candidates: breached staff addresses as takeover monitoring, and the GitHub two-factor requirement.]**

### Multisig Ops module

Parapet reads the owners and threshold of a Safe and reports changes. **[TODO: check whether any control in the Multisig Ops module asks for monitoring of signer changes, and cite it if so.]**

### What is claimed

A Parapet report is a dated, reproducible record that an assessor can accept as evidence for the controls above. Parapet does not certify anything and is not an accredited assessor. No accredited firm has yet agreed to accept its reports. Getting one to do so is a candidate for the integration in Milestone 3.

One DNS finding in the software already links to SEAL Frameworks as a reference. Linking each relevant finding to the specific SEAL control is planned and not built.

## SEAL 911

SEAL 911 is a free emergency hotline, reached through a Telegram bot, that connects an organisation facing an incident with volunteer security researchers. Source: [SEAL 911](https://securityalliance.org/our-work/seal-911).

Parapet is not an incident response service and the maintainer will not act as one. Where a finding suggests an attack may be under way or in preparation, the report points the organisation to SEAL 911. Today three kinds of finding carry the link: a lookalike domain that can receive email, a certificate issued for a name containing the brand, and a staff address found in malware logs. **[TODO: consider adding the link to the finding for a change of treasury signers, which does not carry it today.]**

The aim is to send SEAL 911 fewer and better-informed calls: an organisation that arrives with a dated report of what changed.

**[TODO: before submitting, tell SEAL that the tool points people to SEAL 911, and ask whether they are content with that. Record the answer here.]**

## SEAL-ISAC

SEAL-ISAC is a platform where members share threat intelligence. Source: [SEAL launches a crypto-native ISAC](https://www.securityalliance.org/news/isac_press_release).

Nothing is built here. One possible later link: lookalike domains found by Parapet could be shared with SEAL-ISAC with the organisation's consent. This is an idea and not a commitment.

## Commercial tools

Products that monitor an organisation from outside are sold under names such as external attack surface management and digital risk protection.

### What they cost

Prices were checked on 29 September 2026. Most vendors do not publish prices. The figures that vendors do publish, or that vendors state about each other, are below.

| Product or source | Price | Source |
|---|---|---|
| Hexiosec ASM, Premium plan | £329 per month, up to 300 domains, subdomains and addresses. A free plan covers up to 50 with weekly scans. | [Hexiosec pricing](https://hexiosec.com/asm/pricing/) |
| Microsoft Defender External Attack Surface Management | $0.011 per asset per day | [Microsoft pricing](https://www.microsoft.com/en-us/security/pricing/microsoft-defender-external-attack-surface-management) |
| Intruder, for a small business | From about $10,000 per year, as stated by a competitor's comparison | [Attaxion vendor comparison](https://attaxion.com/top-external-attack-surface-management-vendors/) |
| Mid-market products in general | $25,000 to $75,000 per year, as stated by a vendor | [CyCognito, how to budget](https://www.cycognito.com/blog/how-to-budget-for-easm/) |
| Have I Been Pwned, breach data only | From $4.39 per month for one small domain. $379 per month for the lowest plan that includes malware logs. | [HIBP subscription](https://haveibeenpwned.com/Subscription) |

Two of these figures come from vendors describing the market or a competitor, and should be read with that in mind.

### Why small teams go without

Price is one reason and not the only one. A free plan exists from at least one vendor.

1. **The products are general.** They are built for companies in any industry. The checks that matter most to a crypto team, such as who can sign for the treasury, are outside their scope. **[TODO: verify this against two or three products before submitting, and name any that do cover multisig signers.]**
2. **Several subscriptions are needed.** Outside-in scanning, breach data, lookalike domain monitoring and secret scanning are usually separate products.
3. **The output assumes a security team.** A dashboard with hundreds of items is of little use to a team with nobody assigned to read it. Parapet gives each finding a written fix in plain language.
4. **Closed source.** A crypto team is asked to trust a vendor with a map of its weak points and cannot inspect the software that holds it. Parapet is open source and can be run by the organisation itself.
5. **Procurement.** A sales call and a yearly contract are a barrier for a team of eight people.

### What commercial tools do better

A reviewer will ask, so the proposal should say it. Commercial products have larger data sources, continuous scanning, support staff and years of tuning. An organisation that can afford one and has someone to operate it should consider doing so. Parapet is for the teams that otherwise have nothing.

## Notes for the maintainer (delete before submitting)

- The statement that the fund "does not pick winners" was in the background notes and was not found in the public Round Two announcement. It is not quoted anywhere in these files. If Griff has said it to you, you may use it in your own words.
- The control names in the SEAL table are taken from a summary of the SEAL page. Open the page and copy the exact control identifiers before submitting.
