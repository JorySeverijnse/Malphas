# test/recon/__init__.py
from .sub_scans import subfinder_enum, amass_scan
from .dns_scans import dnsrecon_scan
from .host_scans import httpx_probe, shodan_scan, naabu_scan
from .web_scans import fetch_urls_wayback, gospider_crawl, detect_login_portals, check_open_redirects
from .vuln_scans import (
    nuclei_scan_network, check_lfi, cms_checks, sqlmap_scan,
    zap_spider_scan, openvas_scan, analyze_urls_for_xss,
    analyze_urls_for_domxss, check_xss_advanced
)
from .additional_scans import (
    check_sqli_nuclei, nuclei_scan_web, js_discovery_katana,
    fuzz_endpoints_ffuf, github_secrets_trufflehog
)
