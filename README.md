
# NS Hunter

It is common for web administrators to cause misconfigurations in their domain's name server records.  This can occur for many reasons including typos and orphaned name server domains.  Such misconfigurations could result in an unauthorized third-party hijacking traffic of the victim domain.  If a mistyped name server domain is available (not registered), an attacker can purchase the vulnerable domain and create a DNS server that resolves the victim domain to an attacker controlled IP address.  **NS Hunter** is a multi-threaded Python tool designed to analyze domain name infrastructure for misconfigurations, registration issues, and missing DNS records. It performs fast parallelized checks against large domain lists and outputs deduplicated, color-coded reports with optional JSON support for CI/CD pipelines.

> ✨ Built by **rootcauz**

---

## 🚀 Features

- 🔎 Detects:
  - Domains with no nameservers
  - Nameservers that do not resolve
  - Unregistered nameserver domains
  - Unsupported country code TLDs
- Severity-based reporting (`INFO`, `LOW`, `MED`, `HIGH`, `CRITICAL`)
- Threaded domain scanning for high performance
- Deduplicates and filters findings
- YAML-based ignore list via `.ns_hunter`
- Color-coded CLI output (with `--no-color` option)
- Minimum severity filtering (`--min-severity`)
- Clean JSON output for automation (`--output json`)
- Optional banner and debug logging
- CICD friendly 
  - Standard exit codes
  - JSON output
  - Containerized

---

## Local Installation

1. Clone the repo:

```bash
git clone https://github.com/dhammon/ns-hunter.git
cd ns-hunter
```

2. Set up virtual environment:

```bash
python3 -m virtualenv env
source env/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the tool:

```bash
# Scan a file of domains:
python hunt.py --file src/files/domains1k.txt

#Scan a single domain:
python hunt.py --url example.com
```


## Docker Installation

1. Clone the repo:

```bash
git clone https://github.com/dhammon/ns-hunter.git
cd ns-hunter
```

2. Build the Image:

```bash
docker build -t ns-hunter .
```

3. Run the tool:

```bash
# Scan a file of domains:
docker run --rm -v "$PWD:/data" ns-hunter --file /data/src/files/domains1k.txt

#Scan a single domain:
docker run --rm ns-hunter --url example.com
```


### 🔧 Common options:

| Option | Description |
|--------|-------------|
| `--threads` | Number of threads to use (default: 10) |
| `--output json` | Output results as structured JSON |
| `--no-color` | Disable colored output |
| `--no-banner` | Suppress ASCII art banner |
| `--min-severity` | Only show findings at or above this level |
| `--debug` | Enable verbose logging output |

---

## Ignore Rules

To exclude known or acceptable findings from the report, create a `.ns_hunter` YAML file:

```yaml
ignore:
  - finding_id: 1003
    source: "Nameserver ns1.example.com for domain example.com"

  - finding_id: 1002
    source: "Nameserver ns4.test.com for domain test.com"
```

This will exclude matching `finding_id` + `source` pairs from the final report.

---

## 📑 Sample Output

### CLI Output (default):

```
NS Hunter Report
Run date: 2025-05-03T18:42:00
Number of findings: 3
Severity Summary: HIGH 1 - MED 2 - LOW 0 - INFO 0
====================================================
[MED] 1002:Missing NS Resolution - Nameserver ns4.foo.com for domain foo.com
[MED] 1002:Missing NS Resolution - Nameserver ns2.bar.com for domain bar.com
[HIGH] 1003:NS Domain Not Registered - Nameserver mncplay.biz for domain mncplaymedia.com
```

### JSON Output:

```json
{
  "header": {
    "report_name": "NS Hunter Report",
    "run_date": "2025-05-03T18:42:00",
    "finding_count": 3,
    "severity_summary": "HIGH 1 - MED 2 - LOW 0 - INFO 0"
  },
  "findings": [
    {
      "severity": "MED",
      "finding_id": 1002,
      "description": "Missing NS Resolution",
      "source": "Nameserver ns4.foo.com for domain foo.com"
    }
  ]
}
```

---

## Finding IDs

| ID | Description |
|----|-------------|
| `1000` | Unsupported TLD |
| `1001` | WHOIS returned empty |
| `1002` | Nameserver doesn't resolve |
| `1003` | Nameserver domain not registered |
| `1004` | Domain missing nameserver |
| `9999` | Error |

---

## Exit Codes

| Code | Description |
| ---| ---|
| 0 | Success |
| 1 | Findings |
| 2 | Input Errors |
| 3 | Exceptions |


## Example Domain Input

```text
example.com
bar.com
nonexistentdomain123456.biz
```

---

## Notes

- TLDs such as `.ph`, `.gr`, and other unsupported ccTLDs are skipped with an INFO-level finding.
- WHOIS lookups may be rate-limited or unavailable for certain registries.
- Tool assumes internet access is available for DNS and WHOIS resolution.

---

## 🙏 Acknowledgements

- [`dnspython`](https://www.dnspython.org/)
- [`python-whois`](https://pypi.org/project/python-whois/)
- [`tqdm`](https://tqdm.github.io/)
- [`tldextract`](https://github.com/john-kurkowski/tldextract)

---

## License

MIT License. See `LICENSE` file.