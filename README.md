A set of security tests designed to be ran against a URL designed to be ingested into Splunk 
First run: create some env variables

SPLUNK_HEC_TOKEN=<splunk-hec-token-here>
CENSYS_API_ID=<id>
CENSYS_API_SECRET=<secret>>
NVD_API_KEY=<key>

 Usage: exposures [OPTIONS] COMMAND [ARGS]...                                                                                                                                
                                                                                                                                                                             
 Cyber exposure scanner — scans external URLs for security posture.                                                                                                          
                                                                                                                                                                             
╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                           │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────╮
│ report  Report findings from a scan run, filtered by severity and other criteria.                     │
│ runs    List all recorded scan runs from history.                                                     │
│ diff    Compare two scan runs and show what changed.                                                  │
│ scan    Scan URLs for cyber security exposure.                                                        │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────╯

