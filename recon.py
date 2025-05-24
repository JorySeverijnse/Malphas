import asyncio
import logging
import re
import json
import time
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from gvm.connections import SSHConnection
from gvm.protocols.gmp import Gmp
from .utils import run_cmd, read_file_lines_or_empty

async def dnsrecon_scan(domain: str, output_dir: Path, dnsrecon_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "dnsrecon_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running DNS enumeration for domain: {domain}")
    output_file = output_dir / "dnsrecon.json"
    cmd = [
        dnsrecon_path, "-d", domain, "-t", "std,brt",
        "--lifetime", "10", "-j", str(output_file),
        "-D", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"DNS enumeration completed, output: {output_file}")
            try:
                with output_file.open() as f:
                    data = json.load(f)
                records = [r for r in data if r.get("type") in ["A", "MX", "NS"]]
                logging.debug(f"Found {len(records)} A/MX/NS records")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            except json.JSONDecodeError:
                logging.warning(f"Failed to parse DNSRecon JSON: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
        logging.debug("No DNS records found or dnsrecon failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"DNSRecon failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def subfinder_enum(domain: str, output_dir: Path, subfinder_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "subfinder_enum"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Starting subdomain enumeration for domain: {domain}")
    output_file = output_dir / "subdomains_subfinder.txt"
    cmd = [
        subfinder_path, "-d", domain, "-silent", "-all",
        "-recursive", "-nW", "-o", str(output_file),
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Subdomain enumeration completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No subdomains found or subfinder failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Subfinder failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def amass_enum(domain: str, output_dir: Path, amass_path: str, state: dict, active: bool = False, rate_limit: int = 50) -> Optional[Path]:
    task_name = "amass_enum"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running Amass subdomain enumeration for domain: {domain}")
    output_file = output_dir / "subdomains_amass.txt"
    cmd = [amass_path, "enum", "-d", domain, "-o", str(output_file), "-silent"]
    if not active:
        cmd.append("-passive")
    cmd.extend(["-rps", str(rate_limit)])
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Amass subdomain enumeration completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No subdomains found or amass failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Amass failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def httpx_probe(subdomains_file: Path, output_dir: Path, httpx_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "httpx_probe"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Probing live hosts from: {subdomains_file}")
    output_file = output_dir / "live_hosts_httpx.txt"
    subdomains = read_file_lines_or_empty(subdomains_file)
    threads = min(100, max(10, len(subdomains) * 2))
    cmd = [
        httpx_path, "-l", str(subdomains_file), "-silent", "-o", str(output_file),
        "-threads", str(threads), "-timeout", "15", "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=600)
        if output_file.exists():
            logging.debug(f"Live hosts probing completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No live hosts found or httpx failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Httpx failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def shodan_scan(domain: str, live_hosts_file: Path, output_dir: Path, shodan_path: str, shodan_api_key: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "shodan_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running Shodan scan for domain: {domain}")
    output_file = output_dir / "shodan_results.json"
    
    if not shodan_api_key:
        logging.warning("SHODAN_API_KEY not set. Skipping Shodan scan.")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    # Initialize Shodan
    init_cmd = [shodan_path, "init", shodan_api_key]
    try:
        init_output = await run_cmd(init_cmd)
        if not init_output or "successfully initialized" not in init_output.lower():
            logging.error("Failed to initialize Shodan API key")
            state[task_name] = {"completed": False, "output": None, "error": "Shodan init failed"}
            return None
    except Exception as e:
        logging.error(f"Shodan init failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    # Verify credits with shodan info
    info_cmd = [shodan_path, "info"]
    try:
        info_output = await run_cmd(info_cmd)
        if not info_output:
            logging.error("Shodan info command failed")
            state[task_name] = {"completed": False, "output": None, "error": "Shodan info failed"}
            return None
        
        # Parse credits
        query_credits = 0
        scan_credits = 0
        query_match = re.search(r"Query credits available:\s*(\d+)", info_output)
        scan_match = re.search(r"Scan credits available:\s*(\d+)", info_output)
        
        if query_match:
            query_credits = int(query_match.group(1))
        if scan_match:
            scan_credits = int(scan_match.group(1))
        
        if query_credits < 1 or scan_credits < 1:
            logging.error(f"Insufficient Shodan credits. Query credits: {query_credits}, Scan credits: {scan_credits}")
            state[task_name] = {"completed": False, "output": None, "error": f"Insufficient credits: Query={query_credits}, Scan={scan_credits}"}
            return None
        
        logging.debug(f"Shodan credits verified. Query credits: {query_credits}, Scan credits: {scan_credits}")
    except Exception as e:
        logging.error(f"Shodan info failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    # Run Shodan search
    search_query = f"hostname:{domain}"
    cmd = [
        shodan_path, "search", "--fields", "ip_str,port,org,os,hostnames",
        "--limit", "100", search_query
    ]
    try:
        await run_cmd(cmd, output_file)
        if output_file.exists():
            logging.debug(f"Shodan scan completed, output: {output_file}")
            try:
                with output_file.open() as f:
                    data = json.load(f)
                hosts = data.get("matches", [])
                logging.debug(f"Found {len(hosts)} Shodan hosts")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            except json.JSONDecodeError:
                logging.warning(f"Failed to parse Shodan JSON: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
        logging.debug("No Shodan results found or scan failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Shodan search failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def naabu_scan(subdomains_file: Path, output_dir: Path, naabu_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "naabu_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Scanning ports from: {subdomains_file}")
    output_file = output_dir / "ports_naabu.txt"
    cmd = [
        naabu_path, "-l", str(subdomains_file), "-silent", "-o", str(output_file),
        "-rate", str(rate_limit), "-top-ports", "1000"
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Port scanning completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No ports found or naabu failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Naabu failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def nuclei_scan_network(live_hosts_file: Path, output_dir: Path, nuclei_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "nuclei_scan_network"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running network vulnerability scan from: {live_hosts_file}")
    output_file = output_dir / "vulnerabilities_network_nuclei.txt"
    cmd = [
        nuclei_path, "-l", str(live_hosts_file), "-t", "nuclei-templates/network",
        "-severity", "low,medium,high,critical", "-silent", "-o", str(output_file),
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Network vulnerability scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No network vulnerabilities found or nuclei failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Nuclei network scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def check_lfi(live_hosts_file: Path, output_dir: Path, httpx_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "check_lfi"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Checking LFI from: {live_hosts_file}")
    output_file = output_dir / "lfi_httpx.txt"
    lfi_payloads = ["../../../../etc/passwd", "../../windows/win.ini"]
    cmd = [
        httpx_path, "-l", str(live_hosts_file), "-silent", "-path", ",".join(lfi_payloads),
        "-o", str(output_file), "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"LFI check completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No LFI vulnerabilities found or httpx failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"LFI check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def cms_checks(live_hosts_file: Path, output_dir: Path, httpx_path: str, wpscan_path: str, wpscan_api_token: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "cms_checks"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Checking CMS vulnerabilities from: {live_hosts_file}")
    output_file = output_dir / "cms_vulns.txt"
    wordpress_output = output_dir / "wp_vulns_wpscan.txt"
    
    # CMS paths to check
    cms_paths = [
        "/wp-config.php", "/wp-admin/", "/wp-login.php", "/wp-content/",  # WordPress
        "/configuration.php", "/administrator/",  # Joomla
        "/sites/default/settings.php", "/user/login"  # Drupal
    ]
    cmd = [
        httpx_path, "-l", str(live_hosts_file), "-silent", "-path", ",".join(cms_paths),
        "-sc", "-cl", "-o", str(output_file), "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
    except Exception as e:
        logging.error(f"CMS path check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    # Check for WordPress and run wpscan if detected
    wordpress_detected = False
    if output_file.exists():
        urls = read_file_lines_or_empty(output_file)
        wordpress_indicators = ["/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-config.php"]
        wordpress_urls = [
            url for url in urls
            if any(indicator in url.lower() for indicator in wordpress_indicators) or
               "wp-content" in url.lower()
        ]
        if wordpress_urls:
            wordpress_detected = True
            logging.info("WordPress detected. Running WPScan...")
            temp_file = output_dir / "wordpress_urls.txt"
            with temp_file.open('w') as f:
                f.write('\n'.join(wordpress_urls) + '\n')
            
            wpscan_cmd = [
                wpscan_path, "--url", str(temp_file), "--enumerate", "u,p,t",
                "--output", str(wordpress_output), "--format", "json"
            ]
            if wpscan_api_token:
                wpscan_cmd.extend(["--api-token", wpscan_api_token])
            try:
                await run_cmd(wpscan_cmd)
            except Exception as e:
                logging.error(f"WPScan failed: {e}")
    
    if output_file.exists() or wordpress_output.exists():
        logging.debug(f"CMS checks completed, output: {output_file}, WPScan: {wordpress_output if wordpress_detected else 'N/A'}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.debug("No CMS vulnerabilities found or checks failed")
    state[task_name] = {"completed": True, "output": None}
    return None

async def fetch_urls_wayback(domain: str, output_dir: Path, waybackurls_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "fetch_urls_wayback"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Fetching URLs for domain: {domain}")
    output_file = output_dir / "urls_wayback.txt"
    wayback_cmd = [waybackurls_path, domain]
    try:
        wayback_urls = await run_cmd(wayback_cmd)
        if wayback_urls:
            with output_file.open('w') as f:
                f.write(wayback_urls + '\n')
            logging.debug(f"URL fetching completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No URLs found or waybackurls failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Waybackurls failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def gospider_crawl(domain: str, output_dir: Path, gospider_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "gospider_crawl"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Crawling URLs for domain: {domain}")
    output_file = output_dir / "urls_gospider.txt"
    cmd = [
        gospider_path, "-s", f"https://{domain}", "-o", str(output_file),
        "-d", "3", "--robots", "--sitemap", "--other-source",
        "-r", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"URL crawling completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No URLs found or gospider failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Gospider failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def detect_login_portals(urls_file: Path, output_dir: Path, httpx_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "detect_login_portals"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Detecting login portals from: {urls_file}")
    output_file = output_dir / "login_portals.txt"
    login_paths = ["/login", "/admin", "/signin", "/dashboard", "/wp-login.php", "/user/login"]
    urls = read_file_lines_or_empty(urls_file)
    login_urls = [url for url in urls if any(path in url.lower() for path in login_paths)]
    
    if not login_urls:
        logging.debug("No login portals detected")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    temp_file = output_dir / "login_urls_temp.txt"
    with temp_file.open('w') as f:
        f.write('\n'.join(login_urls) + '\n')
    
    cmd = [
        httpx_path, "-l", str(temp_file), "-silent", "-o", str(output_file),
        "-threads", "50", "-timeout", "15", "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Login portal detection completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No live login portals found or httpx failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Login portal detection failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def sqlmap_scan(login_file: Path, output_dir: Path, sqlmap_path: str, state: dict, level: int = 2, risk: int = 2) -> Optional[Path]:
    task_name = "sqlmap_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running SQLMap on: {login_file}")
    output_file = output_dir / "sqlmap_vulns.txt"
    cmd = [
        sqlmap_path, "-m", str(login_file), "--batch", "--level", str(level),
        "--risk", str(risk), "--forms", "-o", str(output_file)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"SQLMap scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No SQLi vulnerabilities found or sqlmap failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"SQLMap failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def zap_spider_scan(live_hosts_file: Path, output_dir: Path, curl_path: str, zap_api_url: str, zap_api_key: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "zap_spider_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running OWASP ZAP spider scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "zap_spider.json"
    
    if not zap_api_key:
        logging.warning("ZAP_API_KEY not set in config.ini. Skipping OWASP ZAP scan.")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    check_cmd = [curl_path, "-s", zap_api_url]
    try:
        check_output = await run_cmd(check_cmd)
        if not check_output or "ZAP" not in check_output:
            logging.error("OWASP ZAP is not running at %s. Skipping scan.", zap_api_url)
            state[task_name] = {"completed": False, "output": None, "error": "ZAP not running"}
            return None
    except Exception as e:
        logging.error(f"ZAP check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    hosts = read_file_lines_or_empty(live_hosts_file)
    if not hosts:
        logging.warning("No live hosts for ZAP scan. Skipping.")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    results = []
    for host in hosts:
        target_url = host.strip()
        zap_cmd = [
            curl_path, "-s",
            f"{zap_api_url}/JSON/spider/action/scan/?url={target_url}&apikey={zap_api_key}&maxChildren=10"
        ]
        try:
            zap_output = await run_cmd(zap_cmd)
            if zap_output:
                results.append({"url": target_url, "output": zap_output})
        except Exception as e:
            logging.error(f"ZAP scan for {target_url} failed: {e}")
    
    if results:
        with output_file.open('w') as f:
            json.dump(results, f, indent=2)
        logging.debug(f"OWASP ZAP spider scan completed, output: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.debug("No ZAP spider results or scan failed")
    state[task_name] = {"completed": True, "output": None}
    return None

async def openvas_scan(live_hosts_file: Path, output_dir: Path, username: str, password: str, state: dict) -> Optional[Path]:
    task_name = "openvas_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running OpenVAS scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "openvas_scan.json"
    
    if not username or not password:
        logging.warning("OPENVAS_USERNAME or OPENVAS_PASSWORD not set in config.ini. Skipping OpenVAS scan.")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    hosts = read_file_lines_or_empty(live_hosts_file)
    if not hosts:
        logging.warning("No live hosts available for OpenVAS scan. Skipping.")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    for attempt in range(3):
        try:
            connection = SSHConnection(hostname="localhost", username=username, password=password)
            with Gmp(connection) as gmp:
                gmp.authenticate(username, password)
                
                config_name = "Full and fast"
                configs = gmp.get_scan_configs()
                config_id = None
                for config in configs.xpath('config'):
                    if config.findtext('name') == config_name:
                        config_id = config.get('id')
                        break
                if not config_id:
                    logging.error(f"Scan config '{config_name}' not found. Skipping OpenVAS scan.")
                    state[task_name] = {"completed": False, "output": None, "error": "Scan config not found"}
                    return None
                
                target_name = f"ReconNinja_{int(time.time())}"
                target_response = gmp.create_target(name=target_name, hosts=hosts)
                target_id = target_response.get('id')
                if not target_id:
                    logging.error("Failed to create OpenVAS target. Skipping scan.")
                    state[task_name] = {"completed": False, "output": None, "error": "Failed to create target"}
                    return None
                
                task_name_gmp = f"Scan_{int(time.time())}"
                task_response = gmp.create_task(name=task_name_gmp, config_id=config_id, target_id=target_id)
                task_id = task_response.get('id')
                if not task_id:
                    logging.error("Failed to create OpenVAS task. Skipping scan.")
                    state[task_name] = {"completed": False, "output": None, "error": "Failed to create task"}
                    return None
                
                start_response = gmp.start_task(task_id=task_id)
                report_id = start_response.xpath('report_id/text()')[0] if start_response.xpath('report_id') else None
                
                for _ in range(60):
                    task = gmp.get_task(task_id)
                    status = task.xpath('task/status/text()')[0]
                    if status in ["Done", "Stopped", "Interrupted"]:
                        break
                    await asyncio.sleep(5)
                
                result = {
                    "task_id": task_id,
                    "target_id": target_id,
                    "report_id": report_id,
                    "status": status,
                    "hosts": hosts
                }
                with output_file.open('w') as f:
                    json.dump(result, f, indent=2)
                
                logging.debug(f"OpenVAS scan completed, status: {status}, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
        except Exception as e:
            logging.error(f"OpenVAS scan attempt {attempt + 1} failed: {e}")
            if attempt < 2:
                await asyncio.sleep(5)
            continue
    logging.error("OpenVAS scan failed after 3 attempts")
    state[task_name] = {"completed": False, "output": None, "error": "Failed after 3 attempts"}
    return None

async def analyze_urls_for_xss(urls_file: Path, output_dir: Path, dalfox_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "analyze_urls_for_xss"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Analyzing URLs for XSS from: {urls_file}")
    output_file = output_dir / "xss_dalfox.txt"
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file), "-o", str(output_file),
        "--waf-bypass", "--rate-limit", str(rate_limit)
    ]
    try:
        await run_cmd(dalfox_cmd)
        if output_file.exists():
            logging.debug(f"XSS analysis completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No XSS vulnerabilities found or dalfox failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Dalfox XSS scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def analyze_urls_for_domxss(urls_file: Path, output_dir: Path, dalfox_path: str, bxss_url: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "analyze_urls_for_domxss"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Analyzing URLs for DOM XSS from: {urls_file}")
    output_file = output_dir / "domxss_dalfox.txt"
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file), "--only-dom",
        "--waf-bypass", "--rate-limit", str(rate_limit)
    ]
    if bxss_url:
        dalfox_cmd.extend(["--blind", bxss_url])
    dalfox_cmd.extend(["-o", str(output_file)])
    try:
        await run_cmd(dalfox_cmd)
        if output_file.exists():
            logging.debug(f"DOM XSS analysis completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No DOM XSS vulnerabilities found or dalfox failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Dalfox DOM XSS scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def check_xss_advanced(urls_file: Path, output_dir: Path, dalfox_path: str, bxss_url: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "check_xss_advanced"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running advanced XSS checks from: {urls_file}")
    output_file = output_dir / "advanced_xss_dalfox.txt"
    temp_file = output_dir / "xss_params.txt"
    
    xss_params = r'(q|search|id|lang|keyword|query|page|keywords|url|view|name|key|value)=[^&]*'
    urls = read_file_lines_or_empty(urls_file)
    filtered_urls = [url for url in urls if re.search(xss_params, url, re.IGNORECASE)]
    if not filtered_urls:
        logging.debug("No URLs with XSS-prone parameters found")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    with temp_file.open('w') as f:
        f.write('\n'.join(filtered_urls) + '\n')
    
    dalfox_cmd = [
        dalfox_path, "file", str(temp_file), "-o", str(output_file),
        "--waf-bypass", "--rate-limit", str(rate_limit)
    ]
    if bxss_url:
        dalfox_cmd.extend(["--blind", bxss_url])
    try:
        await run_cmd(dalfox_cmd)
        if output_file.exists():
            logging.debug(f"Advanced XSS analysis completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No advanced XSS vulnerabilities found")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Dalfox advanced XSS scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def check_open_redirects(urls_file: Path, output_dir: Path, curl_path: str, redirect_url: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "check_open_redirects"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Checking open redirects from: {urls_file}")
    output_file = output_dir / "open_redirects.txt"
    
    urls = read_file_lines_or_empty(urls_file)
    filtered_urls = [url for url in urls if re.search(r'=http', url, re.IGNORECASE)]
    if not filtered_urls:
        logging.debug("No URLs with =http found")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    modified_urls = []
    for url in filtered_urls:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        modified_params = {}
        for key, values in query_params.items():
            if any('http' in v.lower() for v in values):
                modified_params[key] = [redirect_url]
            else:
                modified_params[key] = values
        new_query = urlencode(modified_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        modified_urls.append(new_url)
    
    vulnerable_urls = []
    for url in modified_urls:
        curl_cmd = [curl_path, "-s", "-L", url, "-I"]
        try:
            curl_output = await run_cmd(curl_cmd)
            if curl_output and redirect_url in curl_output:
                vulnerable_urls.append(url)
        except Exception as e:
            logging.error(f"Open redirect check for {url} failed: {e}")
    
    if vulnerable_urls:
        with output_file.open('w') as f:
            f.write('\n'.join(vulnerable_urls) + '\n')
        logging.debug(f"Open redirects found, output: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.debug("No open redirects found")
    state[task_name] = {"completed": True, "output": None}
    return None

async def check_sqli_nuclei(subdomains_file: Path, urls_file: Path, output_dir: Path, httpx_path: str, nuclei_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "check_sqli_nuclei"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Checking SQLi with Nuclei from subdomains: {subdomains_file}, URLs: {urls_file}")
    output_file = output_dir / "sqli_nuclei.txt"
    temp_file = output_dir / "sqli_urls.txt"
    
    live_hosts_file = output_dir / "live_hosts_sqli.txt"
    httpx_cmd = [
        httpx_path, "-l", str(subdomains_file), "-silent", "-o", str(live_hosts_file),
        "-threads", "50", "-timeout", "15", "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(httpx_cmd, timeout=600)
    except Exception as e:
        logging.error(f"Httpx for SQLi check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    if not live_hosts_file.exists():
        logging.debug("No live hosts for SQLi check")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    urls = read_file_lines_or_empty(urls_file)
    filtered_urls = [url for url in urls if '?' in url]
    if not filtered_urls:
        logging.debug("No URLs with query parameters found")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    with temp_file.open('w') as f:
        f.write('\n'.join(filtered_urls) + '\n')
    
    nuclei_cmd = [
        nuclei_path, "-l", str(temp_file), "-t", "nuclei-templates/vulnerabilities/sqli",
        "-severity", "low,medium,high,critical", "-silent", "-o", str(output_file),
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(nuclei_cmd)
        if output_file.exists():
            logging.debug(f"SQLi scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No SQLi vulnerabilities found")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Nuclei SQLi scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def nuclei_scan_web(urls_file: Path, output_dir: Path, nuclei_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "nuclei_scan_web"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Running web vulnerability scan from: {urls_file}")
    output_file = output_dir / "vulnerabilities_web_nuclei.txt"
    cmd = [
        nuclei_path, "-l", str(urls_file), "-t", "nuclei-templates/http",
        "-severity", "low,medium,high,critical", "-silent", "-o", str(output_file),
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Web vulnerability scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No web vulnerabilities found or nuclei failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Nuclei web scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def js_discovery_katana(live_hosts_file: Path, output_dir: Path, katana_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "js_discovery_katana"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Discovering JS endpoints from: {live_hosts_file}")
    output_file = output_dir / "js_endpoints_katana.txt"
    cmd = [
        katana_path, "-l", str(live_hosts_file), "-silent", "-o", str(output_file),
        "--js-crawl", "--depth", "3", "--crawl-scope", "in-scope",
        "--output-format", "endpoint", "-r", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"JS discovery completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No JS endpoints found or katana failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Katana failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def fuzz_endpoints_ffuf(endpoints_file: Path, output_dir: Path, ffuf_path: str, state: dict, wordlist: str = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt", rate_limit: int = 50) -> Optional[Path]:
    task_name = "fuzz_endpoints_ffuf"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Fuzzing endpoints from: {endpoints_file}")
    output_file = output_dir / "fuzzed_endpoints_ffuf.json"
    temp_file = output_dir / "ffuf_urls.txt"
    
    urls = read_file_lines_or_empty(endpoints_file)
    if not urls:
        logging.debug("No endpoints to fuzz")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    with temp_file.open('w') as f:
        f.write('\n'.join(urls) + '\n')
    
    cmd = [
        ffuf_path, "-u", "FUZZ", "-w", wordlist, "-t", "50",
        "-H", "User-Agent: Mozilla/5.0", "-o", str(output_file), "-of", "json",
        "-i", str(temp_file), "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd)
        if output_file.exists():
            logging.debug(f"Endpoint fuzzing completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No fuzzed endpoints found or ffuf failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Ffuf failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def github_secrets_trufflehog(domain: str, output_dir: Path, trufflehog_path: str, state: dict, rate_limit: int) -> Optional[Path]:
    task_name = "github_secrets_trufflehog"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    logging.debug(f"Scanning GitHub secrets for domain: {domain}")
    output_file = output_dir / f"secrets_trufflehog_github_{domain}.json"
    cmd = [
        trufflehog_path, "github", "--org", domain, "--json",
        "--no-verification", "--rate-limit", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, output_file)
        if output_file.exists():
            logging.debug(f"Secrets scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No secrets found or trufflehog failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except Exception as e:
        logging.error(f"Trufflehog failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
