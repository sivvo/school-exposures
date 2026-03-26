## Cyber exposure scanner — scans external URLs for security posture.   

A set of security tests designed to find vulerabilities through non-destructive/non-malicious means. 
Testing an idea of a centrally provisioned EASM platform for wide-deployment across UK schools

Can create local output (ndjson) or send to Splunk via HEC (not tested in full streaming mode yet - just manual import of the json output)

## First run: create some env variables

- SPLUNK_HEC_TOKEN=<splunk-hec-token-here> # if logging to splunk
- CENSYS_API_ID=<id> # if using censys api (££££)
- CENSYS_API_SECRET=<secret>>
- NVD_API_KEY=<key> # if using NVD (free)

## Then create a CSV of urls (targets to scan) in config/urls.csv

---                                                                                                      

Usage: exposures [OPTIONS] COMMAND [ARGS]...                                                                                                                                      
 
Options 
--help  

## Commands 
 report  Report findings from a scan run, filtered by severity and other criteria.
 runs    List all recorded scan runs from history.                                
 diff    Compare two scan runs and show what changed.                             
 scan    Scan URLs for cyber security exposure.                                   

---
## Functionality / checks:

- HTTP headers:  HSTS, CSP, X-Frame-Options, cookie flags, info leakage

- TLS/certificates: Expiry, weak protocols (TLS 1.0/1.1), self-signed, hostname mismatch

- DNS: DNSSEC, zone transfer (AXFR), dangling CNAMEs (subdomain takeover)

- Email security: SPF, DMARC, MX records

- Exposed services: Risky open ports (RDP, FTP, databases) via Censys; shadow IT ASNs

- Exposed files/tech: .git, .env, phpinfo, known vulnerable software versions

- Cloud storage: Cloud storage exposure
