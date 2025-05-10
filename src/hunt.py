import dns.resolver #pip install dnspython
import whois
import tldextract
import re
import logging
from os.path import isfile
from os.path import exists
from sys import argv
from sys import stdout
from sys import exit
from whois.parser import PywhoisError
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
from tqdm import tqdm
import threading
import yaml
from collections import Counter


FINDINGS = []
FINDINGS_LOCK = threading.Lock()
LOGGER = logging.getLogger("hunt")
logging.getLogger("whois").setLevel(logging.CRITICAL)
UNSUPPORTED = [
    "gr",
    "ph"
]
SEVERITY_COLORS = {
    "INFO": "\033[94m",  # Blue
    "LOW": "\033[96m",  # Cyan
    "MED": "\033[93m",  # Yellow
    "HIGH": "\033[91m",  # Red
    "CRITICAL": "\033[95m",  # Magenta
}
RESET = "\033[0m"
SEVERITY_LEVELS = ["INFO", "LOW", "MED", "HIGH", "CRITICAL"]


def append_finding(finding):
    with FINDINGS_LOCK:
        FINDINGS.append(finding)

def domain_registered(fqdn):
    # false = domain not registered
    domain_components = tldextract.extract(fqdn)
    if domain_components.suffix.split('.')[-1] in UNSUPPORTED:
        message = f"Domain not supported"
        finding = {
            "severity": "INFO",
            "finding_id": 1000,
            "description" : message,
            "source": fqdn
        }
        append_finding(finding)
        LOGGER.debug(f"{message}: {fqdn}")
        return True
    try:
        LOGGER.debug(f"Starting whois lookup {fqdn}")
        w = whois.whois(fqdn)
        if not w or not w.domain_name:
            message = f"WHOIS lookup returned empty result"
            finding = {
                "severity": "INFO",
                "finding_id": 1001,
                "description" : message,
                "source": fqdn
            }
            append_finding(finding)
            LOGGER.debug(f"{message}: {fqdn}")
            return None
        LOGGER.debug(f"Domain registered {fqdn}")
        return True
    except PywhoisError:
        LOGGER.debug(f"Domain not registered {fqdn}")
        return False
    except Exception:
        LOGGER.debug(f"Whois lookup timeout, assuming regsitered {fqdn}")
        return True



def ns_resolution(nameserver):
    #false = nameserver does not resolve
    try:
        nslookup = dns.resolver.resolve(nameserver, 'A')
        if nslookup:
            LOGGER.debug(f"NS domain resolved {nameserver}")
            return True
        LOGGER.debug(f"Ns domain not resolved {nameserver}")
        return False
    except:
        LOGGER.debug(f"Exeception: NS domain not resolved {nameserver}")
        return False


def domain_has_ns(domain):
    #false = domain does not have nameserver
    try:
        resolved = dns.resolver.resolve(domain, 'NS')
        if resolved:
            LOGGER.debug(f"Domain has NS {domain}")
            return True
        LOGGER.debug(f"Domain does not hav a NS {domain}")
        return False
    except:
        LOGGER.debug(f"Exception: Domain does not hav a NS {domain}")
        return False


def domain_exists(domain):
    try:
        dns.resolver.resolve(domain)
        LOGGER.debug(f"Domain resolved {domain}")
        return True
    except:
        LOGGER.debug(f"Domain not resolved {domain}")
        return False
    

def extract_fqdn(nameserver):
    domain_components = tldextract.extract(nameserver)
    fqdn = domain_components.domain + "." + domain_components.suffix
    return fqdn


def is_valid_domain_with_cctld(domain):
    pattern = re.compile(
        r"^(?!\-)(xn--)?[a-zA-Z0-9\-]{1,63}(?<!\-)(\.(xn--)?[a-zA-Z0-9\-]{1,63}(?<!\-))*$"
    )
    return bool(pattern.match(domain))


def hunt_domain_list(file, max_workers=10):
    with open(file) as f:
        domains = [line.strip() for line in f if line.strip()]
    total = len(domains)
    progress = tqdm(
        total=total, 
        desc="Hunting domains", 
        unit="domain", 
        ncols=80,
        leave=False
    )
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(hunt_domain, domain): domain for domain in domains}

        for future in as_completed(futures):
            domain = futures[future]
            try:
                future.result()
            except Exception as e:
                LOGGER.error(f"❌ Error hunting {domain}: {e}")
            finally:
                progress.update(1)
    progress.close()  # Cleanly remove the bar when complete


def hunt_domain(domain):
    try:
        #check if domain has nameservers
        resolved = domain_has_ns(domain)
        if resolved:
            nameservers = dns.resolver.resolve(domain, 'NS')
            for ns in nameservers:
                nameserver = ns.to_text().rstrip('.')

                #check if nameserver resolves
                nslookup = ns_resolution(nameserver)
                if nslookup == False:
                    message = f"Missing NS Resolution"
                    finding = {
                        "severity": "MED",
                        "finding_id": 1002,
                        "description" : message,
                        "source": f"Nameserver {nameserver} for domain {domain}"
                    }
                    append_finding(finding)
                    LOGGER.debug(f"{message}: Nameserver {nameserver} for domain {domain}")

                #check if nameserver domain is registered
                fqdn = extract_fqdn(nameserver)
                registered = domain_registered(fqdn)
                if registered == False:
                    message = f"NS Domain Not Registered"
                    finding = {
                        "severity": "HIGH",
                        "finding_id": 1003,
                        "description" : message,
                        "source": f"Nameserver {fqdn} for domain {domain}"
                    }
                    append_finding(finding)
                    LOGGER.debug(f"{message}: Nameserver {nameserver} for domain {domain}")
        else:
            message = f"Missing NS for domain"
            finding = {
                "severity": "LOW",
                "finding_id": 1004,
                "description" : message,
                "source": domain
            }
            append_finding(finding)
            LOGGER.debug(f"{message}: domain")

    except Exception as e:
        message = f"Error: {e}, {domain}"
        finding = {
            "severity": "INFO",
            "finding_id": 9999,
            "description" : message,
            "source": domain
        }
        append_finding(finding)
        LOGGER.debug(message)


def setup_logger(debug: bool = False):
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.StreamHandler(stdout)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    LOGGER.handlers = []  # Clear old handlers
    LOGGER.addHandler(handler)


def parse_args():
    parser = argparse.ArgumentParser(description="Hunt tool: Analyze input from file or URL")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Path to input file")
    group.add_argument("--url", type=str, help="URL to analyze")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    parser.add_argument("--output", choices=["stdout", "json"], default="stdout", help="Output format: stdout (default) or json")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner output")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in output")
    parser.add_argument("--min-severity", choices=SEVERITY_LEVELS, default="INFO", help="Minimum severity to display (default: show all)")
    return parser.parse_args()


def validate_args(args):
    if args.file:
        if not isfile(args.file):
            LOGGER.error(f"❌ File not found: {args.file}")
            exit(2)
        with open(args.file) as file:
            line = 1
            for domain in file:
                domain = domain.strip()
                if not is_valid_domain_with_cctld(domain):
                    LOGGER.error(f"❌ Invalid Domain: {domain} {args.file}:{line}")
                    exit(2)
                line += 1
    elif args.url:
        if not is_valid_domain_with_cctld(args.url):
            LOGGER.error(f"❌ Invalid URL format: {args.url}")
            exit(2)
    if not (1 <= args.threads <= 50):
        LOGGER.error(f"❌ Invalid thread count {args.threads}: must be between 1 and 50")
        exit(2)
    if args.min_severity.upper() not in SEVERITY_LEVELS:
        LOGGER.error(f"❌ Invalid severity level: {args.min_severity}")
        exit(2)


def should_display(finding_severity, min_severity):
    finding_index = SEVERITY_LEVELS.index(finding_severity.upper())
    min_index = SEVERITY_LEVELS.index(min_severity.upper())
    return finding_index >= min_index


def deduplicate_findings(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("source"), f.get("finding_id"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def load_ignore_config(path=".ns_hunter"):
    if not exists(path):
        LOGGER.debug(f".ns_hunter file not found in current working directory")
        return []
    with open(path, "r") as f:
        config = yaml.safe_load(f) or {}
    return config.get("ignore", [])


def filter_ignored_findings(findings):
    ignore_rules = load_ignore_config()
    ignore_set = {(rule["finding_id"], rule["source"]) for rule in ignore_rules}
    filtered = []
    for f in findings:
        key = (f.get("finding_id"), f.get("source"))
        if key not in ignore_set:
            filtered.append(f)
    return filtered


def print_results(format, min_severity, use_color=True):
    deduped_findings = deduplicate_findings(FINDINGS)
    deduped_findings = filter_ignored_findings(deduped_findings)
    report_name = "NS Hunter Report"
    run_date = datetime.now().isoformat()
    finding_count = len(deduped_findings)
    severity_counts = Counter([f.get("severity").upper() for f in deduped_findings])
    severity_summary = f"HIGH {severity_counts.get('HIGH', 0)} - MED {severity_counts.get('MED', 0)} - LOW {severity_counts.get('LOW', 0)} - INFO {severity_counts.get('INFO', 0)}"
    if format == "json":
        report = {}
        header = {
            "report_name": report_name,
            "run_date": run_date,
            "finding_count": finding_count,
            "severity_summary": severity_summary
        }
        if deduped_findings:
            report = {
                "header": header,
                "findings": deduped_findings
            }
        else:
            report = {
                "header": header,
                "findings": None
            }
        print(json.dumps(report))
    else:  
        #default to stdout
        print(report_name)
        print(f"Run date: {run_date}")
        print(f"Number of findings: {finding_count}")
        print(f"Severity Summary: {severity_summary}")
        print("====================================================")
        if deduped_findings:
            for finding in deduped_findings:
                severity = finding.get("severity", "").upper()
                if use_color:
                    color = SEVERITY_COLORS.get(severity, "")
                    reset = RESET
                else:
                    color = ""
                    reset = ""
                if should_display(severity, min_severity):
                    print(f"[{color}{severity}{reset}] {finding['finding_id']}:{finding['description']} - {finding['source']}")
        else:
            print("No findings!")
    exit(0)


def print_banner():
    banner = r"""

  _   _    _____     _    _                   _                 
 | \ | |  / ____|   | |  | |                 | |                
 |  \| | | (___     | |__| |  _   _   _ __   | |_    ___   _ __ 
 | . ` |  \___ \    |  __  | | | | | | '_ \  | __|  / _ \ | '__|
 | |\  |  ____) |   | |  | | | |_| | | | | | | |_  |  __/ | |   
 |_| \_| |_____/    |_|  |_|  \__,_| |_| |_|  \__|  \___| |_|   
                                                                
                                                                
░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░█░
              Name Server Hunter by rootcauz
"""
    print(f"\033[92m{banner}\033[0m")


if __name__ == "__main__":
    args = parse_args()
    if not args.no_banner:
        print_banner()
    setup_logger(debug=args.debug)
    validate_args(args)
    LOGGER.debug("✅ Starting hunt!")
    if args.url:
        hunt_domain(args.url)
    if args.file:
        hunt_domain_list(args.file, max_workers=args.threads)
    print_results(args.output, args.min_severity, use_color=not args.no_color)
