# tower/summarize.py
import json
import logging
from pathlib import Path
from typing import Dict
from .utils import read_file_lines_or_empty

async def summarize_results(output_dir: Path, summary_file: Path):
    """Summarize scan results into a JSON report."""
    summary: Dict[str, Dict] = {
        "dns": {"records": [], "record_count": 0},
        "subdomains": {"count": 0, "sample": []},
        "live_hosts": {"count": 0, "sample": []},
        "ports": {"count": 0, "sample": []},
        "vulnerabilities": {"network": [], "web": [], "sqli": [], "xss": [], "lfi": [], "open_redirects": []},
        "cms": {"detected": [], "vulnerabilities": []},
        "urls": {"count": 0, "sample": []},
        "login_portals": {"count": 0, "sample": []},
        "openvas": {"status": "N/A", "report_id": None},
        "secrets": {"count": 0, "sample": []},
        "js_endpoints": {"count": 0, "sample": []},
        "fuzzed_endpoints": {"count": 0, "sample": []},
    }

    # DNS Records
    dns_file = output_dir / "dnsrecon.json"
    if dns_file.exists():
        try:
            with dns_file.open() as f:
                data = json.load(f)
            records = [r for r in data if r.get("type") in ["A", "MX", "NS"]]
            summary["dns"]["record_count"] = len(records)
            summary["dns"]["records"] = records[:5]
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse {dns_file}")

    # Subdomains
    subdomain_files = [
        output_dir / "subdomains_subfinder.txt",
        output_dir / "subdomains_amass.txt"
    ]
    subdomains = set()
    for file in subdomain_files:
        if file.exists():
            subdomains.update(read_file_lines_or_empty(file))
    summary["subdomains"]["count"] = len(subdomains)
    summary["subdomains"]["sample"] = list(subdomains)[:5]

    # Live Hosts
    live_hosts_file = output_dir / "live_hosts_httpx.txt"
    if live_hosts_file.exists():
        hosts = read_file_lines_or_empty(live_hosts_file)
        summary["live_hosts"]["count"] = len(hosts)
        summary["live_hosts"]["sample"] = hosts[:5]

    # Ports
    ports_file = output_dir / "ports_naabu.txt"
    if ports_file.exists():
        ports = read_file_lines_or_empty(ports_file)
        summary["ports"]["count"] = len(ports)
        summary["ports"]["sample"] = ports[:5]

    # Vulnerabilities
    vuln_files = {
        "network": output_dir / "vulnerabilities_network_nuclei.txt",
        "web": output_dir / "vulnerabilities_web_nuclei.txt",
        "sqli": output_dir / "sqli_nuclei.txt",
        "xss": output_dir / "xss_dalfox.txt",
        "lfi": output_dir / "lfi_httpx.txt",
        "open_redirects": output_dir / "open_redirects.txt",
    }
    for key, file_path in vuln_files.items():
        if file_path.exists():
            summary["vulnerabilities"][key] = read_file_lines_or_empty(file_path)[:5]

    # CMS
    cms_file = output_dir / "cms_vulns.txt"
    if cms_file.exists():
        summary["cms"]["detected"] = read_file_lines_or_empty(cms_file)[:5]
    wp_file = output_dir / "wp_vulns_wpscan.txt"
    if wp_file.exists():
        try:
            with wp_file.open() as f:
                data = json.load(f)
            summary["cms"]["vulnerabilities"] = data.get("vulnerabilities", [])[:5]
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse {wp_file}")

    # URLs
    url_files = [
        output_dir / "urls_wayback.txt",
        output_dir / "urls_gospider.txt"
    ]
    urls = set()
    for file in url_files:
        if file.exists():
            urls.update(read_file_lines_or_empty(file))
    summary["urls"]["count"] = len(urls)
    summary["urls"]["sample"] = list(urls)[:5]

    # Login Portals
    login_file = output_dir / "login_portals.txt"
    if login_file.exists():
        portals = read_file_lines_or_empty(login_file)
        summary["login_portals"]["count"] = len(portals)
        summary["login_portals"]["sample"] = portals[:5]

    # OpenVAS
    openvas_file = output_dir / "openvas_scan.json"
    if openvas_file.exists():
        try:
            with openvas_file.open() as f:
                data = json.load(f)
            summary["openvas"]["status"] = data.get("status")
            summary["openvas"]["report_id"] = data.get("report_id")
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse {openvas_file}")

    # Secrets
    secrets_file = output_dir / f"secrets_trufflehog_github_{output_dir.name.split('_')[:2][-1]}.json"
    if secrets_file.exists():
        try:
            with secrets_file.open() as f:
                data = json.load(f)
            summary["secrets"]["count"] = len(data)
            summary["secrets"]["sample"] = data[:5]
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse {secrets_file}")

    # JS Endpoints
    js_file = output_dir / "js_endpoints_katana.txt"
    if js_file.exists():
        endpoints = read_file_lines_or_empty(js_file)
        summary["js_endpoints"]["count"] = len(endpoints)
        summary["js_endpoints"]["sample"] = endpoints[:5]

    # Fuzzed Endpoints
    ffuf_file = output_dir / "fuzzed_endpoints_ffuf.json"
    if ffuf_file.exists():
        try:
            with ffuf_file.open() as f:
                data = json.load(f)
            results = data.get("results", [])
            summary["fuzzed_endpoints"]["count"] = len(results)
            summary["fuzzed_endpoints"]["sample"] = results[:5]
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse {ffuf_file}")

    # Save summary
    with summary_file.open('w') as f:
        json.dump(summary, f, indent=2)
