> **DRAFT. Not legal advice. Requires review by a qualified lawyer before use.**

# Opt-out: how to make the traffic stop

Status: draft, published for review. The hosted service has been live in beta at https://perimeterwatch.org since 30 September 2026. No lawyer has reviewed this page, and the service has had no independent security review. The legal documents are drafts under review and are not yet in force. The contact address and the do-not-contact list described here work today.

Last updated: 30 September 2026

This page is for you if you operate a host or a nameserver that received traffic from Perimeterwatch and you want it to stop. You do not need to be a customer. You do not need to give a reason.

## 1. Is the traffic from us?

Web requests from the service carry this User-Agent:

```
perimeterwatch/<version> (+https://perimeterwatch.org; abuse: abuse@perimeterwatch.org)
```

Connections that are not web requests, such as TLS handshakes, port checks, SSH connections and DNS questions, cannot carry a User-Agent. You can recognise them by source address. Scan traffic from the hosted service comes only from these two addresses:

- `162.55.43.236`
- `2a01:4f8:c016:78c3::1`

The software is open source. Anyone can run their own copy. Traffic from someone else's copy will carry the same product name but will come from other addresses and may name another contact. We can only stop traffic from the hosted service. If the traffic comes from someone else's copy, write to the contact in its User-Agent.

## 2. Why did you receive it?

The service contacts a host only when all of these are true:

- the host's name is under a domain that a customer added and proved control of;
- the scan was at probe or active depth;
- the host's name resolved to your address at the time of the scan;
- every address the name resolved to was a public address.

The service contacts a nameserver only when it is listed as a nameserver of such a domain.

The usual reasons an operator who is not the customer sees traffic:

- You provide hosting, a content delivery network or a software service to the customer, and the customer's host name points to your infrastructure.
- You run the nameservers for the customer's domain.
- A customer's DNS record still points to an address that now belongs to you.
- Someone proved control of your domain to the service without your agreement, for example through a DNS account that was taken over. The hosted service scans a domain only once control of it has been proved by a DNS record. If this is your case, tell us. We treat it as an abuse report. See section 7.

## 3. What the traffic is

| Depth | What a host receives | What a nameserver of the domain receives |
|---|---|---|
| Passive | Nothing. No connection is made to hosts under the domain. | One DNS question for the verification record. |
| Probe | One web request, and one TLS handshake on port 443, per host name per scan. A host that answers as a web server also receives one request for its front page and one for each script file that page loads from the same host, at most 40. The domain itself receives one or two requests for its security.txt file. If the domain publishes an MTA-STS record, `mta-sts.<domain>` receives one request for the policy file. | The above, plus about five ordinary DNS questions per scan. |
| Active | The above, plus TCP connection attempts to the 100 most common ports (only ports 80 and 443 if your address belongs to a known content delivery network), plain GET and HEAD requests for known exposure paths, repeated TLS handshakes on port 443 to list the versions and cipher suites accepted, and, if an SSH server was found on port 22 or 2222, a few connections that read what it offers without signing in. | The above, plus one zone transfer request per scan. |

Nothing is exploited. No logins are attempted. No web request carries a body.

The verification record is also checked once a day, and when the customer asks for it to be checked. Each check sends one DNS question to the domain's nameservers.

At active depth, if a DNS name under the domain is an alias for a storage bucket at Amazon S3, Google Cloud Storage or DigitalOcean Spaces, the storage provider is asked what an anonymous visitor may do with that bucket.

The hosted service runs scans of any depth only for a domain whose control has been proved.

A domain is scanned at most once every six hours on request. Scheduled scans run every 24, 72 or 168 hours, as the customer chooses.

## 4. How to ask

Write to abuse@perimeterwatch.org with the subject "Opt-out".

Tell us:

1. The host names, IP addresses or address ranges that should not be contacted.
2. The date and time of the traffic you saw, with the time zone, if you have it.
3. A contact address for our reply.

### Showing that the host is yours

We need some sign that you operate the host, so that nobody can block a customer's scans of its own systems by pretending to be you. Any one of these is enough:

- You write from the abuse or technical contact address registered for the IP address range.
- You write from an address at the domain the host name belongs to.
- You place a text file that we name at a path on the host, or a DNS record that we name.
- You publish the request in the host's own `security.txt` file.

If you cannot do any of these, write anyway. We will look for another way.

## 5. What we do

The service has a do-not-contact list. It is a setting of the service, changed by the operator. An entry can be:

| Kind of entry | What it blocks |
|---|---|
| A host name, such as `host.example.net` | That name and every name under it |
| An IP address | Any host name that resolves to that address |
| A network, such as `198.51.100.0/24` | Any host name that resolves to an address in that network |

If a host name resolves to several addresses and one of them is on the list, the whole host is skipped.

The steps:

| Step | Target time from receiving your request |
|---|---|
| Acknowledge your request | 2 working days |
| Add the host, address or network to the list and restart the scanning worker | 2 working days, once we have a sign that you operate it |
| Confirm to you in writing | 3 working days |
| Find which customer's scan reached you, from the audit log and scan history | 3 working days |
| If the host is not the customer's, tell the customer that its DNS points at someone else's host | 3 working days |

These are targets, not guarantees. The service is run by one person.

The list takes effect for scans that start after the worker has restarted. A scan that is already running when we restart the worker is stopped and started again under the new list.

Once an entry is on the list:

- The web requests, the TLS handshakes, the MTA-STS policy request, the port check, the exposure checks, the SSH check, and the DNS questions and zone transfer requests to nameservers are not sent to it, for any customer and at any depth.
- The customer's report says that the host was not contacted because it is on the do-not-contact list. It does not say who asked.
- The block stays until you ask us to remove it.
- The service may still read public records about the host name, such as DNS records and certificate transparency logs. Those requests go to third parties, not to you.

The list also covers two things that are not requests to a web host. The check of the verification record sends no DNS question to a nameserver on the list: it asks public resolvers instead. The storage bucket check leaves out a bucket when a name that points at it, or the storage address itself, is on the list.

## 6. What we tell you, and what we do not

We tell you:

- whether the traffic came from the hosted service;
- what kind of check it was;
- that it has stopped.

We do not tell you which customer requested the scan, unless the customer agrees or the law requires it. **[LAWYER: confirm.]**

## 7. If you think the scan was not authorised

If you believe someone used the service against your systems without any right to do so, say so in your message. We treat it as an abuse report as well. See section 8 of the [scanning authorisation and acceptable use policy](scanning-authorisation-and-aup.md).

If the domain is yours, you can also take over its verification. Create an account, add the domain, and prove control with the DNS record. Any other organisation that held verification for the domain loses it, and is told through its alert channels if it has set one up. From then on the other account cannot scan the domain. The domain stays on its list, with what was stored earlier, until it is deleted. Ask us if you want that done.

## 8. What we keep

We keep your request, our reply, and the entry on the do-not-contact list. We need the entry for as long as the block is in place. The entry holds a host name or an address, not your name. We keep your request and our reply for 12 months after the matter is closed. See the [data retention policy](data-retention-policy.md).

## 9. If we do not answer

If you have no reply within 5 working days, write to legal@perimeterwatch.org.
