# Teaching and Learning with Domain Doctor

Domain Doctor is free to use as a teaching and learning tool for networking, web infrastructure, cybersecurity, IT support, and systems administration.

**Live site:** https://domaindoctor.fyi

No account is required. Students enter a public hostname and receive an outside-in report covering DNS, TLS, HTTP behavior, redirects, and common browser security headers.

The goal is not to make every website produce all PASS results. The goal is to understand what each result means, what evidence supports it, and why different websites are configured differently.

## What students can learn

| Topic | What Domain Doctor makes visible |
| --- | --- |
| DNS | Whether a hostname resolves and whether it advertises IPv4 or IPv6 |
| TLS | Certificate validity, expiration, hostname coverage, verification, protocol, and cipher information |
| HTTP | Whether a site responds over HTTP and whether it redirects visitors to HTTPS |
| HTTPS | Whether the encrypted web endpoint responds successfully |
| Security headers | Whether common browser security controls are present |
| Troubleshooting | How several infrastructure layers contribute to whether a website works |

A warning does not always mean a site is broken or insecure. For example, IPv6 support is optional, and some security headers are application dependent. Students should interpret results in context rather than treating the report as a score.

## Classroom quick start

1. Open https://domaindoctor.fyi.
2. Enter a public hostname such as `example.com`.
3. Run the diagnostic.
4. Review the overall result.
5. Use the section buttons to explore DNS, TLS, HTTP, and Security.
6. Expand **Details** for checks where deeper technical evidence is useful.
7. Use the status filters to isolate PASS, WARN, or FAIL results.
8. Compare results from several public websites and explain why they differ.

## Activity 1: Follow a web request

**Goal:** Understand the layers involved when a user visits a website.

Run a check against a familiar public website and trace the sequence:

```text
Hostname
  ↓
DNS resolution
  ↓
IP address
  ↓
TLS certificate
  ↓
HTTPS connection
  ↓
HTTP response
```

Discussion questions:

1. What would happen if DNS failed?
2. Why does the certificate need to match the hostname?
3. Why might a site still respond on port 80?
4. What does HTTPS protect?
5. Which layer would you investigate first if a browser reported that the site could not be reached?

## Activity 2: Compare IPv4 and IPv6

Run checks against several public websites and record whether each site advertises IPv4, IPv6, or both.

Discuss why Domain Doctor reports missing IPv6 as a warning rather than a failure. This is a useful example of the difference between a recommended capability and a requirement for service availability.

## Activity 3: Investigate TLS certificates

Choose a public website and inspect its TLS section.

Ask students to identify the certificate validity period, expiration date, hostnames covered by the certificate, whether verification succeeded, and the TLS protocol and cipher information shown in Details.

Discussion questions:

1. What problem does a certificate solve?
2. What happens when a certificate expires?
3. Why must a certificate cover the hostname being visited?
4. What is the difference between establishing a TLS connection and verifying the certificate successfully?

## Activity 4: Study HTTP to HTTPS redirection

Compare websites that redirect HTTP traffic to HTTPS with sites that do not.

Ask students to explain what an HTTP redirect status means, why websites redirect users to HTTPS, and why Domain Doctor tests both the HTTP and HTTPS paths.

## Activity 5: Explore browser security headers

Review the Security section for several sites and research the purpose of these headers:

| Header | Concept to investigate |
| --- | --- |
| Strict-Transport-Security | Telling browsers to prefer HTTPS for future connections |
| Content-Security-Policy | Restricting which resources a browser may load or execute |
| X-Content-Type-Options | Reducing MIME type sniffing behavior |
| Referrer-Policy | Controlling how much referral information browsers send |

Students should explain why the absence of one of these headers can deserve review without necessarily proving that a website is insecure.

## Activity 6: Compare real websites

Choose three public websites with different purposes, such as a government or school website, a large technology company, and a small organization or personal site.

Create a comparison table that records DNS support, TLS health, redirect behavior, HTTPS response, and security header results. Students should explain the differences rather than simply count warnings.

## Troubleshooting exercise

Present students with this scenario:

> Users report that a website cannot be reached securely.

Use Domain Doctor as a layered troubleshooting framework:

1. Does DNS resolve?
2. Does the hostname resolve only to public addresses?
3. Can a TLS connection be established?
4. Is the certificate currently valid?
5. Does the certificate cover the hostname?
6. Does certificate verification succeed?
7. Does HTTPS respond?
8. Does HTTP redirect appropriately?
9. Are common browser security controls present?

This reinforces troubleshooting as a process of gathering evidence at each layer rather than relying on trial and error.

## Student reflection questions

1. What information does DNS provide before a browser can connect?
2. What is the difference between HTTP and HTTPS?
3. What role does a TLS certificate play?
4. Why is certificate hostname validation important?
5. What is a redirect?
6. Why can a warning be acceptable?
7. What is the difference between availability and security?
8. Which diagnostic result surprised you, and why?
9. Which result would be most useful to an IT support technician troubleshooting a user report?

## Appropriate use

Domain Doctor is designed for public web service diagnostics on ports 80 and 443. It is not a vulnerability scanner or penetration testing tool.

For classroom use, prefer well known public websites, example domains, or domains owned by your school or organization. Do not enter private hostnames, internal infrastructure names, or IP addresses. Domain Doctor intentionally blocks private and non-public network destinations.

Do not interpret a WARN result as proof that a website is insecure. Treat each result as evidence that should be interpreted alongside the purpose and architecture of the site being examined.

## For educators

Domain Doctor can support instruction in networking fundamentals, web technologies, cybersecurity, IT support and troubleshooting, systems administration, cloud and infrastructure concepts, career and technical education, and introductory computer science.

It can be used for short demonstrations, guided labs, troubleshooting exercises, comparison activities, or student led investigation. The public site does not require classroom accounts.

Educators are encouraged to adapt the activities in this guide to their own curriculum and student level.

## For students

You do not need to understand every result immediately. Start with the four major sections:

**DNS:** Where does this hostname point?

**TLS:** Can an encrypted connection be established and trusted?

**HTTP:** How does the web server behave?

**Security:** Which common browser protections does the site advertise?

Use the Details controls when you want to see the technical evidence behind a result.

## Learn from the source

Domain Doctor is open source at https://github.com/casual-loops/domain-doctor.

Students interested in software development or systems engineering can inspect how the checks are implemented, review the automated tests, study the container build and CI workflows, or run their own local copy.