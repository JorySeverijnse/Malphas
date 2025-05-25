# test/recon/vuln_scans.py
import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import List, Optional, Dict
from gvm.connections import SSHConnection
from gvm.protocols.gmp import Gmp
from ..utils import read_file_lines_or_empty, run_cmd
from ..config import load_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log'),
        logging.StreamHandler()
    ]
)

async def nuclei_scan_network(
    live_hosts_file: Path,
    output_dir: Path,
    nuclei_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Scan for network vulnerabilities using Nuclei."""
    task_name = "nuclei_scan_network"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(nuclei_path).is_file():
        logging.error(f"Nuclei binary not found: {nuclei_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {nuclei_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None

    logging.info(f"Running network vulnerability scan from: {live_hosts_file}")
    output_file = output_dir / "vulnerabilities_network_nuclei.txt"
    cmd = [
        nuclei_path, "-l", str(live_hosts_file), "-t", "nuclei-templates/network",
        "-severity", "low,medium,high,critical", "-silent", "-o", str(output_file),
        "-rl", str(rate_limit), "-timeout", "10"
    ]
    try:
        for attempt in range(3):
            await run_cmd(cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"Network vulnerability scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Nuclei attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(5)
        logging.info("No network vulnerabilities found or nuclei failed after retries")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Nuclei network scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Nuclei command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Nuclei network scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def check_lfi(
    live_hosts_file: Path,
    output_dir: Path,
    httpx_path: str,
    state: dict,
    rate_limit: int,
    lfi_payloads: Optional[List[str]] = None,
    config_path: str = "config.ini",
    timeout: int = 600
) -> Optional[Path]:
    """Check for Local File Inclusion (LFI) vulnerabilities."""
    task_name = "check_lfi"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None

    if lfi_payloads is None:
        config = load_config(config_path)
        lfi_payloads = config.get("lfi_payloads", [])
    if not lfi_payloads:
        logging.error("No LFI payloads provided")
        state[task_name] = {"completed": False, "output": None, "error": "No LFI payloads provided"}
        return None

    logging.info(f"Checking LFI from: {live_hosts_file}")
    output_file = output_dir / "lfi_httpx.txt"
    results = []
    for payload in lfi_payloads:
        cmd = [
            httpx_path, "-l", str(live_hosts_file), "-silent", "-path", payload,
            "-mc", "200,403", "-o", str(output_file), "-rl", str(rate_limit)
        ]
        try:
            await run_cmd(cmd, timeout=timeout)
            if output_file.exists():
                results.extend(read_file_lines_or_empty(output_file))
        except asyncio.TimeoutError:
            logging.warning(f"LFI check for payload {payload} timed out")
        except Exception as e:
            logging.warning(f"LFI check for payload {payload} failed: {e}")

    if results:
        with output_file.open('w') as f:
            f.write('\n'.join(set(results)) + '\n')
        logging.info(f"LFI check completed, output: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.info("No LFI vulnerabilities found or httpx failed")
    state[task_name] = {"completed": True, "output": None}
    return None

async def cms_checks(
    live_hosts_file: Path,
    output_dir: Path,
    httpx_path: str,
    wpscan_path: str,
    wpscan_api_token: str,
    state: dict,
    rate_limit: int,
    cms_paths: Optional[List[str]] = None,
    config_path: str = "config.ini",
    timeout: int = 600
) -> Optional[Path]:
    """Check for CMS vulnerabilities and perform WPScan if WordPress is detected."""
    task_name = "cms_checks"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not Path(wpscan_path).is_file():
        logging.error(f"WPScan binary not found: {wpscan_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {wpscan_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None

    if cms_paths is None:
        config = load_config(config_path)
        cms_paths = config.get("cms_paths", [])
        if not cms_paths:
            logging.error("No CMS paths provided")
            state[task_name] = {"completed": False, "output": None, "error": "No CMS paths provided"}
            return None

    logging.info(f"Checking CMS vulnerabilities from: {live_hosts_file}")
    output_file = output_dir / "cms_vulns.txt"
    wordpress_output = output_dir / "wp_vulns_wpscan.txt"

    cmd = [
        httpx_path, "-l", str(live_hosts_file), "-silent", "-path", ",".join(cms_paths),
        "-sc", "-cl", "-o", str(output_file), "-rl", str(rate_limit), "-timeout", "15"
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
    except asyncio.TimeoutError:
        logging.error(f"CMS path check timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"CMS path check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

    wordpress_detected = False
    if output_file.exists():
        urls = read_file_lines_or_empty(output_file)
        wordpress_indicators = ["/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-config.php"]
        wordpress_urls = [
            url for url in urls
            if any(indicator in url.lower() for indicator in wordpress_indicators)
        ]
        if wordpress_urls:
            wordpress_detected = True
            logging.info("WordPress detected...")
            temp_file = output_dir / "wordpress_urls.txt"
            with temp_file.open('w') as f:
                f.write('\n'.join(wordpress_urls) + '\n')

            wpscan_cmd = [
                wpscan_path, "-f", "json", "-o", str(wordpress_output),
                "--disable-tls-checks"
            ]
            if wpscan_api_token:
                wpscan_cmd.extend(["--api-token", wpscan_api_token])
            for url in wordpress_urls:
                url_cmd = wpscan_cmd + ["--url", url.strip()]
                try:
                    await run_cmd(url_cmd, timeout=timeout)
                except asyncio.TimeoutError:
                    logging.error(f"WPScan timed out after {timeout} seconds for {url}")
                except FileNotFoundError as e:
                    logging.error(f"WPScan command not found: {e}")
                except Exception as e:
                    logging.error(f"WPScan failed for {url}: {e}")

    if output_file.exists() or wordpress_output.exists():
        logging.info(f"CMS checks completed, output: {output_file}, WPScan: {str(wordpress_output) if wordpress_output.exists() else 'N/A'}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.info("No CMS vulnerabilities found or httpx failed")
    state[task_name] = {"completed": True, "output": None}
    return None

async def sqlmap_scan(
    login_file: Path,
    output_dir: Path,
    sqlmap_path: str,
    state: dict,
    level: int = 2,
    risk: int = 2,
    timeout: int = 600
) -> Optional[Path]:
    """Scan for SQL injection vulnerabilities."""
    task_name = "sqlmap_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(sqlmap_path).is_file():
        logging.error(f"SQLMap binary not found: {sqlmap_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {sqlmap_path}"}
        return None
    if not login_file.exists():
        logging.error(f"Login file not found: {login_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {login_file}"}
        return None
    if not 1 <= level <= 5:
        logging.error(f"Invalid SQLMap level: {level}. Must be 1-5")
        state[task_name] = {"completed": False, "output": None, "error": f"Invalid level: {level}"}
        return None
    if not 1 <= risk <= 3:
        logging.error(f"Invalid SQLMap risk: {risk}. Must be 1-3")
        state[task_name] = {"completed": False, "output": None, "error": f"Invalid risk: {risk}"}
        return None

    logging.info(f"Running SQLMap on: {login_file}")
    output_file = output_dir / "sqlmap_results.txt"
    cmd = [
        sqlmap_path, "-m", str(login_file), "--batch", "--level", str(level),
        "--risk", str(risk), "--forms", "--dbs", "-o", str(output_file)
    ]
    try:
        for attempt in range(2):
            await run_cmd(cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"SQLMap scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"SQLMap attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(5)
        logging.info("No SQLi vulnerabilities found or sqlmap failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"SQLMap timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"SQLMap command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"SQLMap failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def zap_spider_scan(
    live_hosts: Path,
    output_dir: Path,
    curl_path: str,
    zap_api_url: str,
    zap_api_key: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Run OWASP ZAP spider scan on live hosts."""
    task_name = "zap_spider_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(curl_path).is_file():
        logging.error(f"Curl binary not found: {curl_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {curl_path}"}
        return None
    if not live_hosts.is_file():
        logging.error(f"Live hosts file not found: {live_hosts}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts}"}
        return None
    if not zap_api_key:
        logging.warning("ZAP_API_KEY not set in config.ini. Skipping OWASP ZAP scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.info(f"Running OWASP ZAP spider scan for hosts in: {live_hosts}")
    output_file = output_dir / "zap_spider.json"

    check_cmd = [curl_path, "-s", f"{zap_api_url}/JSON/core/view/version/"]
    try:
        check_output = await run_cmd(check_cmd, timeout=30)
        if not check_output or "version" not in check_output.lower():
            logging.error(f"OWASP ZAP is not running at {zap_api_url}. Skipping scan.")
            state[task_name] = {"completed": False, "output": None, "error": "ZAP not running"}
            return None
    except asyncio.TimeoutError:
        logging.error("ZAP check timed out after 30 seconds")
        state[task_name] = {"completed": False, "output": None, "error": "Timeout after 30s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Curl command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"ZAP check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

    hosts = read_file_lines_or_empty(live_hosts)
    if not hosts:
        logging.warning("No live hosts for ZAP scan. Skipping.")
        state[task_name] = {"completed": True, "output": None}
        return None

    results = []
    for host in hosts:
        target_url = host.strip()
        zap_cmd = [
            curl_path, "-s",
            f"{zap_api_url}/JSON/spider/action/scan/?url={target_url}&apiKey={zap_api_key}&maxChildren=10&recurse=true"
        ]
        try:
            zap_output = await run_cmd(zap_cmd, timeout=timeout)
            if zap_output:
                scan_id = json.loads(zap_output).get("scan")
                status_cmd = [curl_path, "-s", f"{zap_api_url}/JSON/spider/view/status/?scanId={scan_id}&apiKey={zap_api_key}"]
                for _ in range(60):
                    status_output = await run_cmd(status_cmd, timeout=30)
                    if status_output and json.loads(status_output).get("status") == "100":
                        break
                    await asyncio.sleep(5)
                results.append({"url": target_url, "output": zap_output})
        except asyncio.TimeoutError:
            logging.error(f"ZAP scan for {target_url} timed out after {timeout} seconds")
        except Exception as e:
            logging.warning(f"ZAP scan for {target_url} failed: {e}")

    if results:
        with output_file.open('w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"OWASP ZAP spider scan completed, output: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.info("No ZAP spider results found")
    state[task_name] = {"completed": True, "output": None}
    return None

async def openvas_scan(
    live_hosts_file: Path,
    output_dir: Path,
    username: Optional[str],
    password: Optional[str],
    state: dict,
    timeout: int = 3600
) -> Optional[Path]:
    """Run OpenVAS vulnerability scan."""
    task_name = "openvas_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not username or not password:
        logging.warning("OpenVAS credentials not set in config.ini. Skipping scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.info(f"Starting OpenVAS scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "openvas_scan.json"
    hosts = read_file_lines_or_empty(live_hosts_file)
    if not hosts:
        logging.warning("No live hosts found for OpenVAS scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    for attempt in range(3):
        try:
            connection = SSHConnection(hostname="localhost", username=username, password=password, timeout=30)
            with Gmp(connection) as gmp:
                gmp.authenticate(username, password)
                config_name = "Full and fast"
                configs = gmp.get_scan_configs()
                config_id = None
                for config in configs.xpath("config"):
                    if config.findtext("name") == config_name:
                        config_id = config.get("id")
                        break
                if not config_id:
                    logging.error(f"Scan config '{config_name}' not found.")
                    state[task_name] = {"completed": False, "output": None, "error": "Scan config not found"}
                    continue

                target_name = f"Target_{int(time.time())}"
                target_response = gmp.create_target(name=target_name, hosts=hosts)
                target_id = target_response.get("id")
                if not target_id:
                    logging.error("Failed to create OpenVAS target.")
                    continue

                task_name_gmp = f"Scan_{int(time.time())}"
                task_response = gmp.create_task(name=task_name_gmp, config_id=config_id, target_id=target_id)
                task_id = task_response.get("id")
                if not task_id:
                    logging.error("Failed to create OpenVAS task.")
                    continue

                start_response = gmp.start_task(task_id)
                report_id = start_response.xpath('report_id/text()')[0] if start_response.xpath('report_id') else None

                for _ in range(600):
                    task = gmp.get_task(task_id)
                    status = task.xpath('task/status/text()')[0]
                    if status in ["Done", "Stopped", "Failed"]:
                        break
                    await asyncio.sleep(10)

                report = gmp.get_report(report_id) if report_id else {}
                result = {
                    "task_id": task_id,
                    "target_id": target_id,
                    "report_id": report_id,
                    "status": status,
                    "hosts": hosts,
                    "report": report,
                }
                with output_file.open('w') as f:
                    json.dump(result, f, indent=4)
                logging.info(f"OpenVAS scan completed: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
        except asyncio.TimeoutError:
            logging.error(f"OpenVAS scan timed out after {timeout} seconds")
            if attempt < 2:
                await asyncio.sleep(10)
            continue
        except Exception as e:
            logging.error(f"OpenVAS scan attempt {attempt + 1} failed: {e}")
            if attempt < 2:
                await asyncio.sleep(5)
            continue
    logging.error("OpenVAS scan failed after 3 attempts")
    state[task_name] = {"completed": False, "output": None, "error": "Failed after 3 attempts"}
    return None

async def analyze_urls_for_xss(
    urls_file: Path,
    output_dir: Path,
    dalfox_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Analyze URLs for XSS vulnerabilities with Dalfox."""
    task_name = "analyze_urls_for_xss"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.exists():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running XSS scan with Dalfox on {urls_file}")
    output_file = output_dir / "xss_dalfox_results.txt"
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file), "-o", str(output_file),
        "--waf-bypass", "--rate-limit", str(rate_limit), "--deep"
    ]
    try:
        for attempt in range(2):
            await run_cmd(dalfox_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"XSS scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Dalfox attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(5)
        logging.info("No XSS vulnerabilities found or dalfox failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Dalfox XSS scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Dalfox command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Dalfox failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def analyze_urls_for_domxss(
    urls_file: Path,
    output_dir: Path,
    dalfox_path: str,
    bxss_url: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Analyze URLs for DOM-based XSS vulnerabilities using Dalfox."""
    task_name = "analyze_urls_for_domxss"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running DOM XSS scan with Dalfox on: {urls_file}")
    output_file = output_dir / "domxss_dalfox.txt"
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file), "--only-dom",
        "--waf-bypass", "--rate-limit", str(rate_limit)
    ]
    if bxss_url:
        dalfox_cmd.extend(["--blind", bxss_url])
    dalfox_cmd.extend(["-o", str(output_file)])
    try:
        for attempt in range(2):
            await run_cmd(dalfox_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"DOM XSS scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Dalfox DOM XSS attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(5)
        logging.info("No DOM XSS vulnerabilities found or dalfox failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"DOM XSS scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Dalfox command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Dalfox DOM XSS scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def check_xss_advanced(
    urls_file: Path,
    output_dir: Path,
    dalfox_path: str,
    bxss_url: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Perform advanced XSS checks on URLs with XSS-prone parameters."""
    task_name = "check_xss_advanced"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running advanced XSS checks from: {urls_file}")
    output_file = output_dir / "advanced_xss_dalfox.txt"
    temp_file = output_dir / "xss_params.txt"

    xss_params = r'(?i)(q|search|id|lang|keyword|query|page|keywords|url|view|name|key|value)=[^&]*'
    urls = read_file_lines_or_empty(urls_file)
    filtered_urls = [url for url in urls if re.search(xss_params, url, re.IGNORECASE)]
    if not filtered_urls:
        logging.info("No URLs with XSS-prone parameters found")
        state[task_name] = {"completed": True, "output": None}
        return None

    with temp_file.open('w') as f:
        f.write('\n'.join(filtered_urls) + '\n')

    dalfox_cmd = [
        dalfox_path, "file", str(temp_file), "-o", str(output_file),
        "--waf-bypass", "--rate-limit", str(rate_limit), "--deep"
    ]
    if bxss_url:
        dalfox_cmd.extend(["--blind", bxss_url])
    try:
        for attempt in range(2):
            await run_cmd(dalfox_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"Advanced XSS analysis completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Dalfox advanced XSS attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(5)
        logging.info("No advanced XSS vulnerabilities found")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Dalfox advanced XSS scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Dalfox command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Dalfox advanced XSS scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
