A set of security tests designed to be ran against a URL designed to be ingested into Splunk 

First run: create some env variables
SPLUNK_HEC_TOKEN=<splunk-hec-token-here>
CENSYS_API_ID=<id>
CENSYS_API_SECRET=<secret>>
NVD_API_KEY=<key>

Then create a CSV of urls (targets to scan)

Cyber exposure scanner — scans external URLs for security posture.                                                                                                          

Usage: exposures [OPTIONS] COMMAND [ARGS]...                                                                                                                                      
 
╭─ Options ────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                      │
╰──────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────╮
│ report  Report findings from a scan run, filtered by severity and other criteria.│
│ runs    List all recorded scan runs from history.                                │
│ diff    Compare two scan runs and show what changed.                             │
│ scan    Scan URLs for cyber security exposure.                                   │
╰──────────────────────────────────────────────────────────────────────────────────╯

Functionality / checks:
  ┌────────────────────┬──────────────────────────────────────────────────────────────────────┐
  │        Area        │                               Examples                               │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ HTTP headers       │ HSTS, CSP, X-Frame-Options, cookie flags, info leakage               │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ TLS/certificates   │ Expiry, weak protocols (TLS 1.0/1.1), self-signed, hostname mismatch │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ DNS                │ DNSSEC, zone transfer (AXFR), dangling CNAMEs (subdomain takeover)   │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Email security     │ SPF, DMARC, MX records                                               │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Exposed services   │ Risky open ports (RDP, FTP, databases) via Censys; shadow IT ASNs    │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Exposed files/tech │ .git, .env, phpinfo, known vulnerable software versions              │
  ├────────────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Cloud storage      │ Cloud storage exposure                                               │
  └────────────────────┴──────────────────────────────────────────────────────────────────────┘

