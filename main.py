import argparse
import asyncio
import logging
import time
import json
from pathlib import Path
from .config import load_config
from .recon.dns_scans import dnsrecon_scan
from .recon.sub_scans import subfinder_enum, amass_scan
from .recon.host_scans import httpx_probe, shodan_scan, naabu_scan
from .recon.vuln_scans import (
    nuclei_scan_network, check_lfi, cms_checks, sqlmap_scan,
    zap_spider_scan, openvas_scan, analyze_urls_for_xss,
    analyze_urls_for_domxss, check_xss_advanced
)
from .recon.web_scans import fetch_urls_wayback, gospider_crawl, detect_login_portals, check_open_redirects
from .recon.additional_scans import (
    check_sqli_nuclei, nuclei_scan_web, js_discovery_katana,
    fuzz_endpoints_ffuf, github_secrets_trufflehog
)
from .summarize import summarize_results

def setup_logging(verbose: bool, output_dir: Path):
    log_file = output_dir / "scan.log"
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def load_state(output_dir: Path) -> dict:
    state_file = output_dir / "state.json"
    if state_file.exists():
        try:
            with state_file.open() as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning("Failed to parse state.json, starting fresh")
    return {}

def save_state(output_dir: Path, state: dict):
    state_file = output_dir / "state.json"
    with state_file.open('w') as f:
        json.dump(state, f, indent=2)

async def main():
    parser = argparse.ArgumentParser(description="Vulnerability Finder Tool")
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("--config", default="config.ini", help="Path to config file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--use-amass", action="store_true", help="Include Amass in subdomain enumeration")
    parser.add_argument("--amass-active", action="store_true", help="Use active mode for Amass")
    parser.add_argument("--skip-cms-scan", action="store_true", help="Skip CMS vulnerability scans")
    parser.add_argument("--sqlmap-level", type=int, default=2, help="SQLMap scan level (1-5)")
    parser.add_argument("--sqlmap-risk", type=int, default=2, help="SQLMap risk level (1-3)")
    parser.add_argument("--rate-limit", type=int, default=50, help="Rate limit for tools (requests per second)")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument("--start-from", help="Start from specific task (e.g., shodan_scan)")
    args = parser.parse_args()

    if args.sqlmap_level < 1 or args.sqlmap_level > 5:
        parser.error("sqlmap-level must be between 1 and 5")
    if args.sqlmap_risk < 1 or args.sqlmap_risk > 3:
        parser.error("sqlmap-risk must be between 1 and 3")
    if args.rate_limit < 1:
        parser.error("rate-limit must be at least 1")

    config = load_config(args.config)
    output_dir = Path("outputs") / f"{args.domain.replace('.', '_')}_{int(time.time())}"
    output_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(args.verbose, output_dir)
    state = load_state(output_dir) if args.resume else {}
    if not state:
        state = {"domain": args.domain, "tasks": {}}

    tasks = [
        ("dnsrecon_scan", lambda: dnsrecon_scan(
            args.domain, output_dir, config["dnsrecon_path"], state["tasks"], args.rate_limit)),
        ("subfinder_enum", lambda: subfinder_enum(
            args.domain, output_dir, config["subfinder_path"], state["tasks"], args.rate_limit)),
        ("amass_enum", lambda: amass_scan(
            args.domain, output_dir, config["amass_path"], state["tasks"], args.amass_active, args.rate_limit)
            if args.use_amass else None),
        ("httpx_probe", lambda: httpx_probe(
            output_dir / "subdomains_subfinder.txt", output_dir, config["httpx_path"], state["tasks"], args.rate_limit)
            if (output_dir / "subdomains_subfinder.txt").exists() else None),
        ("shodan_scan", lambda: shodan_scan(
            args.domain, output_dir / "live_hosts_urls_only.txt", output_dir, config["shodan_path"],
            config["shodan_api_key"], state["tasks"], args.rate_limit)
            if (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("naabu_scan", lambda: naabu_scan(
            output_dir / "subdomains_subfinder.txt", output_dir, config["naabu_path"], state["tasks"], args.rate_limit)
            if (output_dir / "subdomains_subfinder.txt").exists() else None),
        ("nuclei_scan_network", lambda: nuclei_scan_network(
            output_dir / "live_hosts_urls_only.txt", output_dir, config["nuclei_path"], state["tasks"], args.rate_limit)
            if (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("check_lfi", lambda: check_lfi(
            output_dir / "live_hosts_urls_only.txt", output_dir, config["httpx_path"], state["tasks"], args.rate_limit)
            if (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("cms_checks", lambda: cms_checks(
            output_dir / "live_hosts_urls_only.txt", output_dir, config["httpx_path"], config["wpscan_path"],
            config["wpscan_api_token"], state["tasks"], args.rate_limit)
            if not args.skip_cms_scan and (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("fetch_urls_wayback", lambda: fetch_urls_wayback(
            args.domain, output_dir, config["waybackurls_path"], state["tasks"], args.rate_limit)),
        ("gospider_crawl", lambda: gospider_crawl(
            args.domain, output_dir, config["gospider_path"], state["tasks"], args.rate_limit)),
        ("detect_login_portals", lambda: detect_login_portals(
            output_dir / "urls_gospider.txt", output_dir, config["httpx_path"], state["tasks"], args.rate_limit)
            if (output_dir / "urls_gospider.txt").exists() else None),
        ("sqlmap_scan", lambda: sqlmap_scan(
            output_dir / "login_portals.txt", output_dir, config["sqlmap_path"], state["tasks"],
            args.sqlmap_level, args.sqlmap_risk)
            if (output_dir / "login_portals.txt").exists() else None),
        ("zap_spider_scan", lambda: zap_spider_scan(
            output_dir / "live_hosts_urls_only.txt", output_dir, config["curl_path"], config["zap_api_url"],
            config["zap_api_key"], state["tasks"], args.rate_limit)
            if (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("openvas_scan", lambda: openvas_scan(
            output_dir / "live_hosts_urls_only.txt", output_dir, config["openvas_username"],
            config["openvas_password"], state["tasks"])
            if (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("analyze_urls_for_xss", lambda: analyze_urls_for_xss(
            output_dir / "urls_gospider.txt", output_dir, config["dalfox_path"], state["tasks"], args.rate_limit)
            if (output_dir / "urls_gospider.txt").exists() else None),
        ("analyze_urls_for_domxss", lambda: analyze_urls_for_domxss(
            output_dir / "urls_gospider.txt", output_dir, config["dalfox_path"], config["bxss_url"],
            state["tasks"], args.rate_limit)
            if (output_dir / "urls_gospider.txt").exists() else None),
        ("check_xss_advanced", lambda: check_xss_advanced(
            output_dir / "urls_gospider.txt", output_dir, config["dalfox_path"], config["bxss_url"],
            state["tasks"], args.rate_limit)
            if (output_dir / "urls_gospider.txt").exists() else None),
        ("check_open_redirects", lambda: check_open_redirects(
            output_dir / "urls_gospider.txt", output_dir, config["curl_path"], config["redirect_url"],
            state["tasks"], args.rate_limit)
            if (output_dir / "urls_gospider.txt").exists() else None),
        ("check_sqli_nuclei", lambda: check_sqli_nuclei(
            output_dir / "subdomains_subfinder.txt", output_dir / "login_portals.txt", output_dir,
            config["httpx_path"], config["nuclei_path"], state["tasks"], args.rate_limit)
            if (output_dir / "subdomains_subfinder.txt").exists() and (output_dir / "login_portals.txt").exists() else None),
        ("nuclei_scan_web", lambda: nuclei_scan_web(
            output_dir / "urls_gospider.txt", output_dir, config["nuclei_path"], state["tasks"], args.rate_limit)
            if (output_dir / "urls_gospider.txt").exists() else None),
        ("js_discovery_katana", lambda: js_discovery_katana(
            output_dir / "live_hosts_urls_only.txt", output_dir, config["katana_path"], state["tasks"], args.rate_limit)
            if (output_dir / "live_hosts_urls_only.txt").exists() else None),
        ("fuzz_endpoints_ffuf", lambda: fuzz_endpoints_ffuf(
            output_dir / "js_endpoints_katana.txt", output_dir, config["ffuf_path"], state["tasks"],
            config["wordlist"], args.rate_limit)
            if (output_dir / "js_endpoints_katana.txt").exists() else None),
        ("github_secrets_trufflehog", lambda: github_secrets_trufflehog(
            args.domain, output_dir, config["trufflehog_path"], state["tasks"], args.rate_limit)),
    ]

    start_index = 0
    if args.start_from:
        task_names = [t[0] for t in tasks]
        if args.start_from not in task_names:
            parser.error(f"Invalid start-from task: {args.start_from}. Valid tasks: {', '.join(task_names)}")
        start_index = task_names.index(args.start_from)
        logging.info(f"Starting from task: {args.start_from}")

    for task_name, task_func in tasks[start_index:]:
        logging.info(f"Running task: {task_name}")
        try:
            if task_func:
                result = await task_func()
                logging.info(f"Task {task_name} completed with result: {result}")
            else:
                logging.info(f"Skipping task {task_name} (no input or disabled)")
            save_state(output_dir, state)
        except Exception as e:
            logging.error(f"Task {task_name} failed: {e}")
            state["tasks"][task_name] = state["tasks"].get(task_name, {})
            state["tasks"][task_name]["completed"] = False
            state["tasks"][task_name]["error"] = str(e)
            save_state(output_dir, state)

    logging.info("Generating summary report")
    summary_file = output_dir / f"summary_report_{args.domain.replace('.', '_')}.json"
    await summarize_results(output_dir, summary_file)
    logging.info(f"Scan completed. Summary report: {summary_file}")

if __name__ == "__main__":
    asyncio.run(main())
