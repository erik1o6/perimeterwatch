> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Scanning authorisation and acceptable use policy

Status: draft for the hosted service, which has been built but is not yet deployed. It describes what the software does today.

This policy is part of the [terms of service](terms-of-service.md).

## 1. The three depths

A **host** is a named machine or service, such as `app.example.org`. A host is **under your domain** if its name ends with your domain.

### Passive

The service reads public records and indexes kept by others. It makes no connection to your hosts. DNS records are read through public resolvers.

| Check | Where the request goes |
|---|---|
| Hostnames | crt.sh (certificate transparency logs) and the passive sources behind subfinder |
| DNS records | Public DNS resolvers |
| Email security records: SPF, DMARC, DKIM, and whether an MTA-STS record exists | Public DNS resolvers |
| DNS records that point at a resource that no longer exists | Public DNS resolvers |
| Lookalike domains | Public DNS resolvers and crt.sh. Lookalike domains themselves are never contacted. |
| GitHub organisation and public repositories | GitHub |
| Credentials in public repositories | GitHub. Repositories are downloaded, read and deleted. |
| Safe multisig owners and threshold | An Ethereum RPC provider. Two read-only calls per wallet. |
| Technology names in job postings | Greenhouse or Lever |
| Breach exposure | Have I Been Pwned. Needs a verified domain. |

In the hosted service, passive scans run only for a verified domain. The command-line tool can run a passive scan without verification.

### Probe

Everything in passive, and for each host under your domain:

- one ordinary web request, as a browser would make. The request is tried over HTTPS first. If the host does not answer over HTTPS, it is tried over plain HTTP. Redirects are not followed. No retry.
- one TLS handshake on port 443, to read the certificate. One retry if it fails.

And once per scan, if you publish an MTA-STS record: one request for the policy file at `https://mta-sts.<your domain>/.well-known/mta-sts.txt`. It is sent by the service's own web client, with its User-Agent, without following redirects, and only if that host resolves to public addresses and is not on the do-not-contact list. Every mail server that sends you mail makes the same request.

In the hosted service, probe scans run only for a verified domain.

At most 500 hosts are contacted in one scan.

### Active

Everything in probe, and:

- **Open ports.** The service tries an ordinary TCP connection to each of the 100 most common ports on each address. At most 100 connection attempts per second across the whole scan, and at most 200 addresses. For addresses that belong to a content delivery network, only ports 80 and 443 are tried.
- **Known exposures.** The service sends plain GET and HEAD requests for things such as a readable `.git` directory or an open administration page. At most 20 requests per second across the whole scan. No request carries a body or a payload. No out-of-band callbacks are used.

Active depth always needs a verified domain.

### Verification comes first

The hosted service scans a domain only once control of it is proved. This holds for every depth, and for requested and scheduled scans alike. It is checked when the scan is requested and again when the scan starts. If the DNS record cannot be found when the scan starts, the scan does not run.

### How often

- A scan of the same domain can be requested at most once every six hours.
- Scheduled scans run every 24 hours by default. You can choose 72 or 168 hours, or switch them off.
- Scheduled scans run at probe depth. They never run at active depth. A domain that is not verified is skipped.

## 2. What is never done at any depth

- No attempt to exploit a weakness.
- No password guessing and no login attempts.
- No testing of a found credential.
- No requests that change data: only GET and HEAD.
- No denial-of-service testing.
- No contact with a host outside your domain.
- No contact with a host that resolves to a private or reserved address. If even one of a host's addresses is private or reserved, the host is skipped.
- No contact with lookalike domains.
- No contact with a host or address on the do-not-contact list. See the [opt-out policy](opt-out.md).

## 3. Domain verification

### What you do

You create a DNS TXT record:

| | |
|---|---|
| Name | `_perimeterwatch-verify.<your domain>` |
| Value | `pw-verify=<token>` |

### How it is checked

The answer must come from your domain's own authoritative nameservers. If they cannot be reached, at least two of three independent public resolvers must return the record. A local resolver cannot satisfy the check.

The record is checked again before every scan, and once a day. Keep it in place.

If the record cannot be found when a scan starts, that scan does not run. After three failed checks in a row, verification is withdrawn until you prove control again.

### One organisation at a time

Only one organisation at a time can hold verification of a domain. If another organisation proves control of your domain, your verification is withdrawn. You are told through your alert channels, if you have set one up. If you did not expect this, check who can change your DNS.

### What verification authorises

- Scans of the domain and of hosts under it, at the depth you select.
- Scheduled scans at probe depth.
- Findings that name individual email addresses at the verified domain.

### What verification does not authorise

- Scanning any other domain, including other domains you own. Each domain is verified separately.
- Scanning hosts that your DNS records point to but whose names are not under your domain.
- Anything listed in section 2.
- Anything that the owner of the underlying infrastructure forbids. See section 5.

### What verification does not prove

Verification proves that someone could edit the domain's DNS. It does not prove that the person had the legal authority to approve security testing. That is why the terms of service also require your promise that you are authorised. **[LAWYER: see README open question 13.]**

### Withdrawing authorisation

Remove the DNS record. From the next check, scans of the domain stop. You can also delete the domain from your account, which stops all scans of it and deletes what is stored about it.

Findings about people that were stored while the domain was verified are withheld once verification is lost: they cannot be opened, and a report with personal details shown cannot be downloaded. They are not deleted until you delete the domain. **[NOT YET BUILT: deleting them. LAWYER: see README open question 30.]**

## 4. The command-line tool only: typed acknowledgement

The open-source command-line tool has a second way to authorise active checks, for a user who cannot edit DNS. **The hosted service does not offer it, and its scanning worker ignores any such statement.**

- The user types their name, organisation and role, the domain, and the sentence "I am authorised to test `<domain>`".
- The statement is stored with the time, the computer's name and the user's login name. It is protected against later alteration by a keyed hash.
- It is valid for 30 days.
- It is printed at the top of every report it enables, with the note that domain control was not proven.
- It never unlocks findings about individual people.
- The record is deleted by the retention run once it has been expired for longer than the retention period.

## 5. Hosts on infrastructure owned by others

A host under your domain often runs on someone else's infrastructure. Examples:

- a content delivery network in front of your website;
- a cloud provider's virtual machine or load balancer;
- a software-as-a-service product on a name such as `status.<your domain>` or `shop.<your domain>`.

Your verification covers your domain name. It does not override the terms of the provider that owns the machine. Those terms also apply.

What the service does about this:

- For addresses that belong to a known content delivery network, the port check tries only ports 80 and 443.
- Exposure checks use only plain GET and HEAD requests.

What the service does not do:

- It does not detect every shared platform.
- It does not read any provider's terms for you.

What you must do before selecting probe or active depth:

1. Check which providers host your systems.
2. Read each provider's policy on security testing.
3. If a provider requires notice or approval, obtain it.
4. If a provider forbids it, do not select that depth.

## 6. Prohibited uses

You must not:

1. Add a domain that you do not own and are not authorised to have scanned.
2. Create a verification record for a domain by means you are not entitled to use, such as a compromised DNS account.
3. Use the service to learn about a competitor, a target of an attack, or any organisation other than your own.
4. Upload email addresses of people who do not work for you.
5. Use breach findings to discipline, dismiss or disadvantage a person for having been the victim of a breach.
6. Use breach findings to try to sign in to anyone's account.
7. Use a found credential for any purpose other than revoking it.
8. Resell findings, or use them to provide a breach search service.
9. Remove the Have I Been Pwned attribution from breach data you share.
10. Run scans at a rate or frequency meant to disturb a host.
11. Try to get around a limit, a block or a suspension.
12. Use the service in a way that breaks the law that applies to you.

## 7. How the service identifies itself

Web requests sent by the service carry a User-Agent in this form:

```
perimeterwatch/<version> (+<contact URL>; abuse: <abuse address>)
```

| | |
|---|---|
| Contact URL | **[TO DECIDE: contact URL]** |
| Abuse address | **[TO DECIDE: abuse contact address]** |
| Source IP addresses | **[TO DECIDE: published list of addresses the hosted service scans from]** |

TLS handshakes, port checks and DNS queries cannot carry a User-Agent. They can be recognised by source IP address. Requests to third-party sources made by the bundled subdomain tool and repository scanner carry those tools' own User-Agent.

Outside development mode, the web service refuses to start unless an abuse address is set.

## 8. Abuse reports

An **abuse report** is a message saying that the service was used against a system without permission, or in breach of this policy.

### How to report

Write to **[TO DECIDE: abuse contact address]**. Please include:

- the host name or IP address that received traffic;
- the date, time and time zone;
- a sample of your logs, if you can share one;
- how to reach you.

You do not need to prove who you are to make a report. We will need proof that you operate the host before we tell you anything about the scan.

### What we do

| Step | Target time |
|---|---|
| Acknowledge the report | **[TO CONFIRM: 2 working days]** |
| Check the audit log for scans that match | **[TO CONFIRM: 2 working days]** |
| If traffic is continuing, add the host to the do-not-contact list while we look into it | **[TO CONFIRM: 1 working day]** |
| Tell you the outcome | **[TO CONFIRM: 10 working days]** |

The do-not-contact list is described in the [opt-out policy](opt-out.md).

**[NOT YET BUILT: a function for our staff to suspend a domain or an account. Until it exists, suspension is done by hand in the database.]**

### Possible outcomes

- The traffic was not ours. We tell you so.
- The scan was authorised by the verified owner of the domain, and you run infrastructure that the domain points to. We tell the customer, and we stop contacting your host if you ask. See the [opt-out policy](opt-out.md).
- The customer was not authorised. We suspend the domain or the account and delete the findings.

### What we tell you

We confirm whether the traffic came from the service and what kind of check it was. We do not name the customer without its agreement, unless the law requires it. **[LAWYER: confirm.]**

### Records

We keep abuse reports and our replies for **[TO DECIDE: retention period for abuse reports]**.
