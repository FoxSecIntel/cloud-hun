# Free Security Data Sources

This page curates free and community-accessible security APIs, feeds, and lookup services that pair well with `cloud-hun` findings.

Use these sources for enrichment and prioritization. Respect each provider's terms, rate limits, attribution requirements, and commercial-use restrictions.

## Vulnerability intelligence

| Source | Data | Auth | Notes | Useful `cloud-hun` use |
| --- | --- | --- | --- | --- |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited CVEs, vendor, product, due dates | No | Available as web, CSV, JSON, and JSON schema | Highlight exposed assets related to vulnerabilities known to be exploited |
| [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) | CVE records, CVSS, CWE, references, CPE matching | Optional API key | API key improves practical request handling for regular use | Map product exposure to vulnerability metadata |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability and percentile by CVE | No | API and daily CSV are published freely | Sort remediation candidates by exploit likelihood |
| [OSV.dev](https://google.github.io/osv.dev/api/) | Open-source package vulnerabilities | No | Supports package/version and batch queries | Check project dependencies, SBOMs, and cloud-deployed package inventories |

## Threat intelligence and IOC enrichment

| Source | Data | Auth | Notes | Useful `cloud-hun` use |
| --- | --- | --- | --- | --- |
| [URLhaus](https://urlhaus.abuse.ch/api/) | Malware URLs and payload metadata | Free abuse.ch auth key for many API actions | Community API supports download and submission workflows | Check URLs discovered in public buckets, scripts, logs, or config files |
| [MalwareBazaar](https://bazaar.abuse.ch/api/) | Malware hashes, samples, tags, families | Free abuse.ch auth key for sample download and some workflows | Handle samples safely; downloaded malware is password-protected | Enrich suspicious hashes found in exposed storage or deployment artifacts |
| [ThreatFox](https://threatfox.abuse.ch/api/) | Malware IOCs: IPs, domains, URLs, hashes | Free / fair use | Commercial or high-volume use may require paid access | Add IOC context to exposed hosts, domains, and leaked indicators |
| [AlienVault OTX](https://otx.alienvault.com/api) | Community threat pulses and indicators | Free account/API key for authenticated integration | Good breadth; community signal quality varies | Add pulse and indicator context to IPs, domains, URLs, and hashes |
| [VirusTotal Public API](https://docs.virustotal.com/reference/public-vs-premium-api) | File, URL, domain, and IP reputation | Free API key | Public API is rate-limited and restricted for commercial workflows | Manual or low-volume enrichment only; do not build noisy automation around it |

## IP, domain, and internet exposure context

| Source | Data | Auth | Notes | Useful `cloud-hun` use |
| --- | --- | --- | --- | --- |
| [GreyNoise Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api) | IP scanner and internet-noise context | Free API key | Community endpoint is suited to quick IP lookups | Distinguish commodity scanner traffic from more targeted-looking activity |
| [AbuseIPDB](https://docs.abuseipdb.com/) | IP abuse reports and reputation | Free API key | Free account supports practical daily checks for small workflows | Add abuse confidence to public IP findings |
| [Censys](https://docs.censys.com/reference/get-started) | Host, certificate, and web property lookup | Free account/API credentials | Free users have limited lookup access, not full search coverage | Validate external exposure and certificate context |
| [Shodan](https://developer.shodan.io/api/requirements) | Internet-exposed services and host metadata | Free account/API key | Query credits and account tier determine practical access | Cross-check public services and exposed ports from scan output |
| [crt.sh](https://crt.sh/) | Certificate Transparency search | No | Unofficial JSON-style usage is common; availability can vary | Discover subdomains and certificate names tied to a target domain |
| [Cloudflare Radar](https://developers.cloudflare.com/radar/) | Internet traffic, routing, domain, and threat trend data | Free API token | Data is published under Cloudflare Radar terms and CC BY-NC 4.0 | Add broader internet context to campaign or domain observations |

## Selection guidance

- Prefer sources with no secret material for default examples.
- Keep API keys in environment variables; never commit them.
- Use caching and backoff for any API integration.
- Treat free-tier limits as product constraints, not just implementation details.
- Show enrichment as optional context; `cloud-hun` findings should still stand on first-party cloud evidence.

## Good first integrations

1. CISA KEV lookup for CVE-based prioritization.
2. EPSS score enrichment for CVEs.
3. GreyNoise Community lookup for public IP findings.
4. AbuseIPDB lookup for public IP findings.
5. URLhaus or ThreatFox lookup for discovered URLs, domains, IPs, and hashes.
