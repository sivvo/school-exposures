# Legal basis for scanning activity — Computer Misuse Act 1990

The directly relevant precedent is NCSC's Web Check & Mail Check service
   Their stated legal basis: *"scanning and notifications are
   based on external observations, such as the version number publicly advertised by
   the software."* 

## Risk tiers

- **Tier 1** Passive third-party dataset queries, or
  ordinary public-web/DNS interaction indistinguishable from what a browser & recursive
  resolver does. No access-control bypass, no retrieval of anything the operator didn't choose to publish.
- **Tier 2** No access-control bypass and nothing retrieved beyond
  existence/pattern-matching, but the check does check locations outside ordinary user activity
- **Tier 3** Active checks, such as port scan. Never enabled by default.

---

## Tier 1 checks

### `http_headers`
**What it does:** Fetches the public homepage over HTTP/HTTPS, reads response headers
and cookies, follows redirects.
**Justification:** Identical to what any browser does when loading a
public page. No authentication bypassed, nothing requested beyond the page the
operator chose to serve publicly.

### `mixed_content`
**What it does:** Fetches the public homepage HTML (capped 200KB), scans for
`http://` sub-resource references.
**Justification:** Same basis as `http_headers` (reading the content of a page the
operator already serves to any visitor)

### `tls`
**What it does:** Standard TLS handshake to the public HTTPS port.
**Justification:** A TLS handshake is client-initiated protocol negotiation by
design — the server chooses what it accepts. This is exactly what Qualys SSL Labs'
public scanner does at internet scale, uncontroversially. No data
is accessed through a weak-cipher/weak-protocol connection.

### `dns_records` (A/AAAA/CAA/DNSSEC/dangling-CNAME sub-checks)
**What it does:** Standard DNS resolution against records the domain's own
nameservers are configured to answer publicly.
**Justification:** DNS is a public directory protocol by design. Every recursive
resolver on earth does this continuously.

### `email_security`
**What it does:** DNS TXT/MX record lookups (SPF, DMARC, MX presence).
**Justification:** Same basis as `dns_records` — reading public DNS records the
domain owner published specifically so any mail server on the internet can read them.

### `components` — header-fingerprinting tier, `robots.txt`, `security.txt`
**What it does:** Reads `Server`/`X-Powered-By`/etc. from the same page fetch as
`http_headers`; fetches `/robots.txt` and `/.well-known/security.txt`.
**Justification:** Header fingerprinting is the exact methodology NCSC Web Check
stated it used. `robots.txt` and `security.txt` are protocols *specifically published
for automated/security-researcher consumption*.
**Does not include** the well-known-path probing (`.git/HEAD`, admin panels, etc).

### `censys_ports`
**What it does:** Queries Censys's own pre-collected internet-scan dataset via API.
**Justification:** Passive, we never send a single packet to the target infrastructure.

### `open_redirect`
**What it does:** Appends a query parameter with a canary URL, checks the redirect
target.
**Justification:** An ordinary GET request with a query parameter — happens on every
website constantly (UTM params, search params, etc.).

### `cert_transparency` (and the CT-log half of `subdomain_enum`)
**What it does:** Queries the public Certificate Transparency log aggregator.
**Justification:** Passive third-party query against infrastructure (CT logs) that
exists *specifically* to be publicly, exhaustively queryable.

### `cloud_storage`
**What it does:** Resolves CNAME/redirect chains, then makes a GET request to the
resolved storage endpoint (S3/Azure Blob/GCS/R2).
**Justification:** The request lands on the cloud provider's public edge
infrastructure, the exact same request any ordinary visitor would trigger if their DNS/redirects route there.

### `domain_expiry`
**What it does:** One WHOIS lookup per domain.
**Justification:** Explicitly public directory protocol run by registries
specifically to be queried by anyone.

### `safe_browsing`
**What it does:** Queries Google's Safe Browsing API about a URL.
**Justification:** Third-party reputation API query.

### `dnsbl`
**What it does:** DNS-based blocklist lookups (Spamhaus ZEN) against mail server IPs.
**Justification:** Standard, ubiquitous practice. Every mail server on the internet
performs this exact type of lookup on every inbound message.

### `subdomain_enum` — CT-log half, and the dangling-CNAME liveness check
**Justification:** CT-log portion — same as `cert_transparency` above. The
liveness check (an HTTP GET to see if a discovered subdomain responds) is the same
character as `open_redirect` — an ordinary request, no bypass.


---

## Tier 2 checks 

### `dns_records` — AXFR zone-transfer sub-check
**What it does:** Attempts a DNS zone transfer against each of the domain's
nameservers.
**Justification:** A universally recognised DNS-hygiene check performed by every
mainstream DNS security scanner; AXFR is refused by default unless deliberately
misconfigured, so attempting it is not inherently hostile, and there's no way to know
a nameserver is misconfigured without asking. **Already mitigated by design**: on a
successful transfer, the code stores only *which* nameservers allowed it
(`evidence.vulnerable_nameservers`), never the actual zone contents — so even a
"successful" attempt doesn't compound the exposure by retaining the disclosed data.

### `components` — well-known-path probing (`.git/HEAD`, admin panels, MIS logins, etc.)
**What it does:** GET requests to ~25 specific, non-linked paths, checking for a
200 response and (where specified) a body-content pattern match.
**Justification:** Still a standard GET request to whatever's publicly routable, no
access control bypassed, no credential guessing or login attempted. Deliberately
targeting locations outside the public sitemap is qualitatively different from
loading the homepage, even though nothing is technically "broken into" to reach them.

### `subdomain_enum` — DNS brute-force wordlist
**What it does:** Queries DNS for ~60 common subdomain name guesses per domain.
**Justification:** Borderline, logged here deliberately rather than folded into
Tier 1. Mechanically this is just DNS resolution (as low-footprint as network
activity gets)

---

## Tier 3 

### `port_scan`
**What it does:** Opens raw TCP connections directly to ~17 ports (chosen because
they're sensitive: databases, RDP, VNC, Telnet, FTP) against every target.
**Why this is different from everything else in this document:** every other check
is either passive (a third party did the touching, under their own authorisation) or
a standard web/DNS interaction with content the operator chose to publish. This is
not passive. We are directly, actively connecting. **Not enabled - and may never be** 

---
