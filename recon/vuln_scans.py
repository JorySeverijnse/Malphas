import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import List, Optional, Dict
from gvm.connections import SSHConnection # Make sure python-gvm is installed
from gvm.protocols.gmp import Gmp # Make sure python-gvm is installed
from ..utils import read_file_lines_or_empty, run_cmd
from ..config import load_config

# Configure logging (Consider moving to a central logging setup if not already)
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('scan.log'), # This might be relative to where script is run
#         logging.StreamHandler()
#     ]
# )

async def nuclei_scan_network(
    live_hosts_file: Path,
    output_dir: Path,
    nuclei_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Scan for network vulnerabilities using Nuclei."""
    config_data = load_config(config_path)
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
    # Added JSON output for consistency, similar to other Nuclei scans
    output_file_json = output_dir / "vulnerabilities_network_nuclei.json"
    
    cmd = [
        nuclei_path, "-l", str(live_hosts_file),
        "-t", config_data['nuclei_network_template_path'],
        "-severity", config_data['nuclei_network_severity'],
        "-silent", "-o", str(output_file),
        "-json", str(output_file_json), # Added JSON output
        "-rl", str(rate_limit),
        "-timeout", str(config_data['nuclei_common_flag_timeout']),
        "-retries", str(config_data['nuclei_common_retries']) # Using common retries, can use _alt if needed
    ]
    try:
        # Using nuclei_network_retries_alt for the loop, nuclei_common_retries for the flag
        for attempt in range(config_data['nuclei_network_retries_alt']):
            await run_cmd(cmd, timeout=timeout)
            # Check JSON output first, then TXT
            if output_file_json.exists() and output_file_json.stat().st_size > 0:
                logging.info(f"Network vulnerability scan completed, output: {output_file_json}")
                state[task_name] = {"completed": True, "output": str(output_file_json)}
                return output_file_json
            elif output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"Network vulnerability scan completed (TXT output): {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Nuclei attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(config_data['nuclei_common_retry_delay_seconds'])
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
    lfi_payloads: Optional[List[str]] = None, # Kept as param, loaded from config if None
    config_path: str = "config.ini",
    timeout: int = 600
) -> Optional[Path]:
    """Check for Local File Inclusion (LFI) vulnerabilities."""
    config_data = load_config(config_path)
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

    current_lfi_payloads = lfi_payloads if lfi_payloads is not None else config_data.get("lfi_payloads", [])
    if not current_lfi_payloads:
        logging.error("No LFI payloads provided or found in config")
        state[task_name] = {"completed": False, "output": None, "error": "No LFI payloads"}
        return None

    logging.info(f"Checking LFI from: {live_hosts_file}")
    # Create a consolidated output file, rather than per-payload then combining
    # However, httpx -path takes a single path or a file of paths.
    # The current loop per payload is fine to generate one output file per payload and then merge,
    # or to run httpx multiple times appending to a conceptual list.
    # Let's stick to one output file and append results.
    
    final_output_file = output_dir / "lfi_httpx.txt"
    all_results_set = set()
    
    temp_payload_output_file = output_dir / "lfi_httpx_temp_payload.txt"

    for payload in current_lfi_payloads:
        # Each httpx run will overwrite or create temp_payload_output_file
        cmd = [
            httpx_path, "-l", str(live_hosts_file), "-silent", "-path", payload,
            "-mc", config_data['httpx_lfi_match_codes'], 
            "-o", str(temp_payload_output_file), # Output to temp file for this payload
            "-rl", str(rate_limit)
        ]
        try:
            await run_cmd(cmd, timeout=timeout) # Consider a shorter timeout per payload
            if temp_payload_output_file.exists() and temp_payload_output_file.stat().st_size > 0:
                payload_results = read_file_lines_or_empty(temp_payload_output_file)
                for res in payload_results:
                    all_results_set.add(res)
                temp_payload_output_file.unlink(missing_ok=True) # Clean up temp file
        except asyncio.TimeoutError:
            logging.warning(f"LFI check for payload {payload} timed out")
        except Exception as e:
            logging.warning(f"LFI check for payload {payload} failed: {e}")

    if all_results_set:
        with final_output_file.open('w') as f:
            for item in sorted(list(all_results_set)): # Sort for consistent output
                 f.write(item + '\n')
        logging.info(f"LFI check completed, output: {final_output_file}")
        state[task_name] = {"completed": True, "output": str(final_output_file)}
        return final_output_file
        
    logging.info("No LFI vulnerabilities found or httpx failed for all payloads")
    state[task_name] = {"completed": True, "output": None}
    return None

async def cms_checks(
    live_hosts_file: Path,
    output_dir: Path,
    httpx_path: str,
    wpscan_path: str,
    wpscan_api_token: str, # Passed directly
    state: dict,
    rate_limit: int,
    cms_paths: Optional[List[str]] = None, # Loaded from config if None
    config_path: str = "config.ini",
    timeout: int = 600
) -> Optional[Path]:
    """Check for CMS vulnerabilities and perform WPScan if WordPress is detected."""
    config_data = load_config(config_path)
    task_name = "cms_checks"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not Path(wpscan_path).is_file() and any("wp" in p.lower() for p in config_data.get("cms_paths",[])): # Check if wpscan needed
        logging.warning(f"WPScan binary not found: {wpscan_path}, WordPress scans will be skipped if WP detected.")
        # Do not return yet, other CMS checks might run
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None

    current_cms_paths = cms_paths if cms_paths is not None else config_data.get("cms_paths", [])
    if not current_cms_paths:
        logging.error("No CMS paths provided or found in config")
        state[task_name] = {"completed": False, "output": None, "error": "No CMS paths provided"}
        return None

    logging.info(f"Checking CMS vulnerabilities from: {live_hosts_file}")
    # This output_file is for general CMS path detection by httpx
    generic_cms_output_file = output_dir / "cms_detected_paths.txt" 
    wordpress_scan_output_file = output_dir / "wp_vulns_wpscan.json" # WPScan output

    # Use httpx to check for existence of various CMS paths
    # httpx -path can take comma separated list
    httpx_cms_cmd = [
        httpx_path, "-l", str(live_hosts_file), "-silent", 
        "-path", ",".join(current_cms_paths), # httpx can probe multiple paths
        "-sc", "-cl", # Show status code and content length
        "-o", str(generic_cms_output_file), 
        "-rl", str(rate_limit), 
        "-timeout", str(config_data['httpx_cms_paths_flag_timeout'])
    ]
    try:
        await run_cmd(httpx_cms_cmd, timeout=timeout)
    except asyncio.TimeoutError:
        logging.error(f"CMS path check (httpx) timed out after {timeout} seconds")
        # Continue to WPScan if httpx managed to write some results before timeout
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None # httpx is crucial here
    except Exception as e:
        logging.error(f"CMS path check (httpx) failed: {e}")
        # Continue if possible, or decide to return

    wordpress_detected_urls = []
    if generic_cms_output_file.exists() and generic_cms_output_file.stat().st_size > 0:
        detected_urls_content = read_file_lines_or_empty(generic_cms_output_file)
        current_wordpress_indicators = config_data.get('wordpress_indicators', [])
        
        # Extract base URLs that showed WordPress indicators
        # Assuming detected_urls_content contains lines like: http://example.com/wp-admin [200]
        processed_wp_base_urls = set()

        for line in detected_urls_content:
            url_match = re.match(r"^(https?://[^/]+)", line) # Get scheme and domain
            if url_match:
                base_url = url_match.group(1)
                if any(indicator.lower() in line.lower() for indicator in current_wordpress_indicators):
                    if base_url not in processed_wp_base_urls:
                         wordpress_detected_urls.append(base_url)
                         processed_wp_base_urls.add(base_url)
        
        if wordpress_detected_urls:
            logging.info(f"WordPress detected on: {', '.join(wordpress_detected_urls)}")
            if not Path(wpscan_path).is_file():
                logging.warning(f"WPScan binary not found ({wpscan_path}), skipping WordPress scans.")
            else:
                # Create a temporary file for WPScan targets if needed, or pass one by one
                # WPScan typically scans one URL at a time from its --url flag.
                all_wpscan_results = [] # To store structured results if possible

                for wp_url in wordpress_detected_urls:
                    logging.info(f"Running WPScan on: {wp_url}")
                    # WPScan outputs to stdout if -o is not specified for a single run,
                    # or to a file. For multiple targets, best to manage output per target or use API for batch.
                    # Let's create a per-target output file then merge, or append to a JSON list.
                    # For simplicity, we'll just run it and rely on its combined output if -o is used.
                    # However, wpscan -o overwrites. So we need to handle multiple WP sites.
                    # The current script calls wpscan per URL and appends to wordpress_output.
                    # This means wordpress_output would ideally be a JSON array.
                    # WPScan JSON output for a single scan isn't an array element by default.
                    # Let's assume wordpress_scan_output_file will store an array of JSON objects.
                    
                    temp_wpscan_output_json = output_dir / f"wpscan_{Path(wp_url).name}.json"

                    wpscan_cmd_base = [wpscan_path]
                    if config_data['wpscan_output_format_json']:
                        wpscan_cmd_base.extend(["-f", "json"])
                    
                    # Output to a temporary file for this specific URL
                    wpscan_cmd_base.extend(["-o", str(temp_wpscan_output_json)])

                    if config_data['wpscan_disable_tls_checks_flag']:
                        wpscan_cmd_base.append("--disable-tls-checks") # Changed to use new flag
                    
                    if wpscan_api_token:
                        wpscan_cmd_base.extend(["--api-token", wpscan_api_token])
                    
                    current_wpscan_cmd = wpscan_cmd_base + ["--url", wp_url.strip()]
                    
                    try:
                        await run_cmd(current_wpscan_cmd, timeout=timeout) # Long timeout for wpscan
                        if temp_wpscan_output_json.exists() and temp_wpscan_output_json.stat().st_size > 0:
                            with temp_wpscan_output_json.open('r') as f_temp_json:
                                try:
                                    scan_data = json.load(f_temp_json)
                                    all_wpscan_results.append({"url": wp_url.strip(), "scan_data": scan_data})
                                except json.JSONDecodeError:
                                    logging.error(f"Failed to decode WPScan JSON for {wp_url}")
                            temp_wpscan_output_json.unlink(missing_ok=True) # clean up
                    except asyncio.TimeoutError:
                        logging.error(f"WPScan timed out after {timeout} seconds for {wp_url}")
                    except Exception as e: # Catches FileNotFoundError for wpscan too if not checked prior
                        logging.error(f"WPScan failed for {wp_url}: {e}")
                
                if all_wpscan_results:
                    with wordpress_scan_output_file.open('w') as f_final_wpscan:
                        json.dump(all_wpscan_results, f_final_wpscan, indent=2)
                    logging.info(f"WPScan results saved to {wordpress_scan_output_file}")

    # Determine overall success and output file for the state
    # The primary output of this function could be the generic CMS detection,
    # or the WPScan results if WordPress was found and scanned.
    final_output_for_state = None
    if wordpress_scan_output_file.exists() and wordpress_scan_output_file.stat().st_size > 0:
        final_output_for_state = wordpress_scan_output_file
    elif generic_cms_output_file.exists() and generic_cms_output_file.stat().st_size > 0:
        final_output_for_state = generic_cms_output_file
        
    if final_output_for_state:
        logging.info(f"CMS checks completed. Main output: {final_output_for_state}")
        state[task_name] = {"completed": True, "output": str(final_output_for_state)}
        return final_output_for_state
        
    logging.info("No significant CMS findings or issues in CMS/WPScan checks.")
    state[task_name] = {"completed": True, "output": None}
    return None

async def sqlmap_scan(
    login_file: Path, # This should be a file with multiple URLs if sqlmap -m is used
    output_dir: Path,
    sqlmap_path: str,
    state: dict,
    level: int = 2, # Kept as param, could also be from config
    risk: int = 2,  # Kept as param, could also be from config
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Scan for SQL injection vulnerabilities using SQLMap."""
    config_data = load_config(config_path)
    task_name = "sqlmap_scan"

    # Use config for level and risk if not overridden by params, or always use config
    current_level = level if level != config_data.get('sqlmap_level') else config_data.get('sqlmap_level', 2)
    current_risk = risk if risk != config_data.get('sqlmap_risk') else config_data.get('sqlmap_risk', 2)


    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(sqlmap_path).is_file():
        logging.error(f"SQLMap binary not found: {sqlmap_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {sqlmap_path}"}
        return None
    if not login_file.exists(): # Assuming login_file contains URLs for sqlmap -m
        logging.error(f"Input file for SQLMap not found: {login_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {login_file}"}
        return None
    if not 1 <= current_level <= 5:
        logging.error(f"Invalid SQLMap level: {current_level}. Must be 1-5")
        state[task_name] = {"completed": False, "output": None, "error": f"Invalid level: {current_level}"}
        return None
    if not 1 <= current_risk <= 3:
        logging.error(f"Invalid SQLMap risk: {current_risk}. Must be 1-3")
        state[task_name] = {"completed": False, "output": None, "error": f"Invalid risk: {current_risk}"}
        return None

    logging.info(f"Running SQLMap on URLs from: {login_file}")
    # SQLMap output is a directory by default when using -o.
    # The -o flag actually enables session saving and output dir.
    # For a single text file report, you might pipe output or parse sqlmap's log.
    # Let's assume we want sqlmap to manage its output in a dir, and we record this dir.
    # Or, if sqlmap can output a single report file, that's better.
    # Sqlmap's direct output often goes to stdout. --o means output dir.
    # For a single file result, often people use --csv or parse session files.
    # The original script used -o str(output_file) assuming it's a file, sqlmap might treat it as prefix.
    # Let's create an output directory for sqlmap results.
    sqlmap_output_dir = output_dir / f"sqlmap_{login_file.stem}"
    sqlmap_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Sqlmap command construction
    cmd = [
        sqlmap_path, "-m", str(login_file),
        "--level", str(current_level),
        "--risk", str(current_risk),
        "--output-dir", str(sqlmap_output_dir) # Directing all output to this folder
    ]
    if config_data.get('sqlmap_options_batch', True):
        cmd.append("--batch")
    if config_data.get('sqlmap_options_forms', False): # Typically forms are for single URL with -u
        cmd.append("--forms") # May not be ideal with -m, sqlmap will decide.
    if config_data.get('sqlmap_options_dbs', False):
        cmd.append("--dbs")
    # Add other flags like --threads, --random-agent etc. from config if desired

    # sqlmap does not have a simple single output file for vulnerabilities from -m.
    # We will consider the task successful if sqlmap completes and the output dir is made.
    # Parsing results from sqlmap_output_dir is a separate, more complex task.
    # For now, the output returned will be the directory.

    try:
        # SQLMap can take a very long time. Retrying might not be ideal without state.
        # The original script had a retry loop.
        for attempt in range(1): # Reduced retries, SQLMap state is complex
            await run_cmd(cmd, timeout=timeout) # Long timeout for SQLMap
            # Check if the output directory was created and has content (e.g., log file)
            log_file = sqlmap_output_dir / "log" # A common file in sqlmap output dir
            if log_file.exists() and log_file.stat().st_size > 0:
                logging.info(f"SQLMap scan completed, output directory: {sqlmap_output_dir}")
                state[task_name] = {"completed": True, "output": str(sqlmap_output_dir)}
                return sqlmap_output_dir
            logging.warning(f"SQLMap attempt {attempt + 1} seems to have not produced output, retrying if configured...")
            if attempt < 0 : # Effectively no script-level retries here unless changed
                 await asyncio.sleep(config_data['sqlmap_retry_delay_seconds'])
        
        # If loop finishes without returning, it means no output or sqlmap failed.
        # Check one last time if dir exists, even if log is not there.
        if sqlmap_output_dir.exists():
            logging.info(f"SQLMap scan ran, output directory: {sqlmap_output_dir}. Content not verified by script.")
            state[task_name] = {"completed": True, "output": str(sqlmap_output_dir)} # Mark as completed with dir
            return sqlmap_output_dir

        logging.info("No SQLi vulnerabilities found by SQLMap or SQLMap process issue.")
        state[task_name] = {"completed": True, "output": None} # Or mark as failed if dir not found
        return None
        
    except asyncio.TimeoutError:
        logging.error(f"SQLMap timed out after {timeout} seconds. Check output directory: {sqlmap_output_dir}")
        # Even on timeout, sqlmap might have created partial results.
        if sqlmap_output_dir.exists():
            state[task_name] = {"completed": False, "output": str(sqlmap_output_dir), "error": f"Timeout after {timeout}s, partial results may exist."}
            return sqlmap_output_dir
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"SQLMap command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"SQLMap failed: {e}. Check output directory: {sqlmap_output_dir}")
        if sqlmap_output_dir.exists():
             state[task_name] = {"completed": False, "output": str(sqlmap_output_dir), "error": f"SQLMap failed: {e}, partial results may exist."}
             return sqlmap_output_dir
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def zap_spider_scan(
    live_hosts_file: Path, # Changed from live_hosts to live_hosts_file for clarity
    output_dir: Path,
    curl_path: str, # Make sure curl is available
    zap_api_url: str, # Passed directly
    zap_api_key: str, # Passed directly
    state: dict,
    rate_limit: int, # Not directly used by ZAP API spider, more for controlling our script's calls
    timeout: int = 600, # Overall timeout for each ZAP interaction
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Run OWASP ZAP spider scan on live hosts via API."""
    config_data = load_config(config_path)
    task_name = "zap_spider_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(curl_path).is_file():
        logging.error(f"Curl binary not found: {curl_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {curl_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not zap_api_key:
        logging.warning("ZAP_API_KEY not set/passed. Skipping OWASP ZAP spider scan.")
        state[task_name] = {"completed": True, "output": None}
        return None
    if not zap_api_url: # Check if ZAP API URL is provided
        logging.warning("ZAP_API_URL not set/passed. Skipping OWASP ZAP spider scan.")
        state[task_name] = {"completed": True, "output": None}
        return None


    logging.info(f"Running OWASP ZAP spider scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "zap_spider_results.json" # Store all results here

    # Check ZAP API is responsive
    zap_version_url = f"{zap_api_url.rstrip('/')}/JSON/core/view/version/?apikey={zap_api_key}"
    check_cmd = [curl_path, "-s", zap_version_url]
    try:
        check_output_str = await run_cmd(check_cmd, timeout=config_data['zap_check_timeout_seconds'])
        if not check_output_str or "version" not in json.loads(check_output_str): # Basic check
            logging.error(f"OWASP ZAP API not responding as expected at {zap_api_url}. Skipping scan. Response: {check_output_str[:100]}")
            state[task_name] = {"completed": False, "output": None, "error": "ZAP API not responding"}
            return None
    except json.JSONDecodeError:
        logging.error(f"Failed to decode ZAP version check JSON: {check_output_str[:100]}")
        state[task_name] = {"completed": False, "output": None, "error": "ZAP version check decode error"}
        return None
    except asyncio.TimeoutError:
        logging.error(f"ZAP API check timed out after {config_data['zap_check_timeout_seconds']} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {config_data['zap_check_timeout_seconds']}s"}
        return None
    except Exception as e: # Catch other errors like FileNotFoundError for curl
        logging.error(f"ZAP API check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

    hosts = read_file_lines_or_empty(live_hosts_file)
    if not hosts:
        logging.warning("No live hosts for ZAP spider scan. Skipping.")
        state[task_name] = {"completed": True, "output": None}
        return None

    all_spider_results = []
    for host_url in hosts: # Each host is a URL like http://target.com
        target_url = host_url.strip()
        if not target_url:
            continue
        
        logging.info(f"Starting ZAP spider for: {target_url}")
        # Spider Scan Action
        spider_action_url = (
            f"{zap_api_url.rstrip('/')}/JSON/spider/action/scan/?"
            f"url={target_url}&maxChildren={config_data['zap_spider_max_children']}"
            f"&recurse={str(config_data['zap_spider_recurse']).lower()}&contextName=&subtreeOnly=false&apikey={zap_api_key}"
        )
        spider_cmd = [curl_path, "-s", spider_action_url]
        scan_id = None
        try:
            spider_action_output_str = await run_cmd(spider_cmd, timeout=timeout) # General timeout for API call
            if spider_action_output_str:
                scan_id = json.loads(spider_action_output_str).get("scan")
            if not scan_id:
                logging.warning(f"Failed to start ZAP spider for {target_url} or get scan ID. Response: {spider_action_output_str[:100]}")
                all_spider_results.append({"url": target_url, "status": "failed_to_start", "scan_id": None, "spider_results_count": 0})
                continue
            
            logging.info(f"ZAP spider started for {target_url} with scan ID: {scan_id}. Waiting for completion...")
            # Poll Spider Status
            status_url_template = f"{zap_api_url.rstrip('/')}/JSON/spider/view/status/?scanId={{scan_id}}&apikey={zap_api_key}"
            
            for i in range(config_data['zap_status_check_retries']):
                status_url = status_url_template.format(scan_id=scan_id)
                status_cmd = [curl_path, "-s", status_url]
                status_output_str = await run_cmd(status_cmd, timeout=config_data['zap_check_timeout_seconds'])
                
                if status_output_str:
                    status_json = json.loads(status_output_str)
                    current_status_percentage = status_json.get("status", "0")
                    logging.info(f"ZAP spider status for {target_url} (Scan ID: {scan_id}): {current_status_percentage}% ({i+1}/{config_data['zap_status_check_retries']})")
                    if current_status_percentage == "100":
                        logging.info(f"ZAP spider completed for {target_url} (Scan ID: {scan_id})")
                        break
                await asyncio.sleep(config_data['zap_status_check_delay_seconds'])
            else: # Loop finished without break
                logging.warning(f"ZAP spider for {target_url} (Scan ID: {scan_id}) did not reach 100% status after {config_data['zap_status_check_retries']} attempts.")

            # Get Spider Results
            results_url = f"{zap_api_url.rstrip('/')}/JSON/spider/view/results/?scanId={scan_id}&apikey={zap_api_key}"
            results_cmd = [curl_path, "-s", results_url]
            spider_results_str = await run_cmd(results_cmd, timeout=timeout)
            spider_results_data = json.loads(spider_results_str).get("results", []) if spider_results_str else []
            
            all_spider_results.append({
                "url": target_url, 
                "status": "completed_polling", # Or check final status from status_json
                "scan_id": scan_id, 
                "spider_results_count": len(spider_results_data),
                # "results_detail": spider_results_data # Optionally include full results
            })

        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error during ZAP spider for {target_url}: {e}")
            all_spider_results.append({"url": target_url, "status": "json_error", "scan_id": scan_id, "spider_results_count": 0})
        except asyncio.TimeoutError:
            logging.error(f"ZAP spider interaction for {target_url} timed out.")
            all_spider_results.append({"url": target_url, "status": "timeout", "scan_id": scan_id, "spider_results_count": 0})
        except Exception as e:
            logging.warning(f"ZAP spider scan for {target_url} failed: {e}")
            all_spider_results.append({"url": target_url, "status": f"error: {str(e)[:50]}", "scan_id": scan_id, "spider_results_count": 0})
        
        # Optional: Add a small delay between targets if rate limiting API calls
        await asyncio.sleep(1) # Small delay

    if all_spider_results:
        with output_file.open('w') as f:
            json.dump(all_spider_results, f, indent=2)
        logging.info(f"OWASP ZAP spider scans processed, summary report: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
        
    logging.info("No ZAP spider results generated (or all scans failed).")
    state[task_name] = {"completed": True, "output": None}
    return None

async def openvas_scan(
    live_hosts_file: Path,
    output_dir: Path,
    username: Optional[str], # Passed, from config originally
    password: Optional[str], # Passed, from config originally
    state: dict,
    timeout: int = 3600, # Overall timeout for GVM interaction for a task
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Run OpenVAS/GVM vulnerability scan using python-gvm."""
    config_data = load_config(config_path)
    task_name = "openvas_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not username or not password:
        logging.warning("OpenVAS credentials not set/passed. Skipping OpenVAS scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.info(f"Starting OpenVAS scan for hosts in: {live_hosts_file}")
    # Output will be a JSON file containing scan details and report summary/ID
    output_file = output_dir / f"openvas_scan_{live_hosts_file.stem}.json"
    
    hosts_to_scan = read_file_lines_or_empty(live_hosts_file)
    if not hosts_to_scan:
        logging.warning("No live hosts found in file for OpenVAS scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    gvm_connection_host = config_data['openvas_connection_host']
    gvm_connection_timeout = config_data['openvas_connection_timeout_seconds']
    scan_config_name = config_data['openvas_scan_config_name']
    target_name_prefix = config_data['openvas_target_name_prefix']
    task_name_prefix = config_data['openvas_task_name_prefix']
    status_check_retries = config_data['openvas_status_check_retries']
    status_check_delay = config_data['openvas_status_check_delay_seconds']
    # openvas_retry_delay_seconds is for the outer loop if we implement multiple GVM connection attempts

    # This function will attempt the entire GVM process once. 
    # Retries for connection/setup are complex with GVM state.
    try:
        # Using asyncio.wait_for for the entire GVM block for a simpler timeout
        async def gvm_process():
            nonlocal state # Allow modification of state from outer scope
            connection = None
            try:
                # Note: python-gvm's SSHConnection is blocking. 
                # For true async, gvm-tools or direct GMP over async socket would be needed.
                # Here, we run it in a thread implicitly via await if run_cmd was async,
                # but direct Gmp calls are blocking. This might block the asyncio loop.
                # Consider using asyncio.to_thread for Gmp interactions if issues arise.
                
                logging.info(f"Connecting to GVM at {gvm_connection_host}...")
                connection = SSHConnection(
                    hostname=gvm_connection_host, 
                    username=username, 
                    password=password, 
                    timeout=gvm_connection_timeout
                )
                
                with Gmp(connection=connection) as gmp:
                    logging.info("Authenticating to GVM...")
                    gmp.authenticate(username, password)
                    
                    # Get Scan Config ID
                    logging.debug(f"Fetching scan config ID for '{scan_config_name}'...")
                    configs_xml = gmp.get_scan_configs()
                    config_id = None
                    for config_element in configs_xml.xpath('config'):
                        if config_element.findtext('name') == scan_config_name:
                            config_id = config_element.get('id')
                            break
                    if not config_id:
                        logging.error(f"Scan config '{scan_config_name}' not found.")
                        state[task_name] = {"completed": False, "output": None, "error": "Scan config not found"}
                        return None
                    logging.debug(f"Found Scan Config ID: {config_id}")

                    # Create Target
                    target_name = f"{target_name_prefix}{int(time.time())}"
                    logging.info(f"Creating GVM target '{target_name}' with hosts: {hosts_to_scan[:3]}...")
                    # Ensure hosts_to_scan is a list of strings
                    hosts_list_str = [str(h).strip() for h in hosts_to_scan if str(h).strip()]
                    target_response_xml = gmp.create_target(name=target_name, hosts=hosts_list_str)
                    target_id = target_response_xml.get('id')
                    if not target_id:
                        logging.error("Failed to create OpenVAS target.")
                        state[task_name] = {"completed": False, "output": None, "error": "Failed to create GVM target"}
                        return None
                    logging.info(f"GVM Target '{target_name}' created with ID: {target_id}")

                    # Create Task
                    gmp_task_name = f"{task_name_prefix}{int(time.time())}"
                    logging.info(f"Creating GVM task '{gmp_task_name}'...")
                    task_response_xml = gmp.create_task(name=gmp_task_name, config_id=config_id, target_id=target_id)
                    task_id = task_response_xml.get('id')
                    if not task_id:
                        gmp.delete_target(target_id) # Clean up target
                        logging.error("Failed to create OpenVAS task.")
                        state[task_name] = {"completed": False, "output": None, "error": "Failed to create GVM task"}
                        return None
                    logging.info(f"GVM Task '{gmp_task_name}' created with ID: {task_id}")

                    # Start Task
                    logging.info(f"Starting GVM task ID: {task_id}...")
                    start_response_xml = gmp.start_task(task_id)
                    # Report ID is often available once task finishes, or from get_reports
                    # For simplicity, we'll fetch the report ID later if needed.
                    # report_id_from_start = start_response_xml.xpath('report_id/text()') # Might not be there
                    # report_id = report_id_from_start[0] if report_id_from_start else None

                    logging.info(f"GVM Task {task_id} started. Monitoring progress...")
                    final_task_status = "Unknown"
                    for i in range(status_check_retries):
                        task_details_xml = gmp.get_task(task_id)
                        final_task_status = task_details_xml.xpath('task/status/text()')[0]
                        progress = task_details_xml.xpath('task/progress/text()')
                        progress_text = progress[0] if progress and progress[0]!="-1" else "N/A"
                        
                        logging.info(f"GVM Task {task_id} status: {final_task_status}, progress: {progress_text}% ({i+1}/{status_check_retries})")
                        if final_task_status in ["Done", "Stopped", "Failed"]:
                            break
                        await asyncio.sleep(status_check_delay) # release to asyncio loop
                    else: # Loop finished without break
                        logging.warning(f"GVM Task {task_id} did not complete within polling window. Last status: {final_task_status}")
                    
                    logging.info(f"GVM Task {task_id} finished with status: {final_task_status}")
                    
                    # Get Report for the completed task
                    # There should be one report associated with this task run.
                    report_id_final = None
                    reports_xml = gmp.get_reports(filter_string=f"task_id={task_id} rows=1") # Get latest report for task
                    report_elements = reports_xml.xpath('report')
                    if report_elements:
                        report_id_final = report_elements[0].get('id')
                        logging.info(f"Found Report ID for task {task_id}: {report_id_final}")
                        
                        # Fetch the report content (e.g., in XML or PDF)
                        # For this script, we'll just store the IDs and status.
                        # report_content_xml = gmp.get_report(report_id=report_id_final, details=True)
                        # report_format_id for PDF: 'c402cc3e-b531-11e1-9163-406186ea4fc5'
                    else:
                        logging.warning(f"No report found directly for GVM task {task_id}. Status was {final_task_status}.")

                    scan_result_summary = {
                        "gvm_target_name": target_name,
                        "gvm_target_id": target_id,
                        "gvm_task_name": gmp_task_name,
                        "gvm_task_id": task_id,
                        "gvm_task_final_status": final_task_status,
                        "gvm_report_id": report_id_final,
                        "scanned_hosts": hosts_list_str,
                        "scan_config_used": scan_config_name,
                        "output_file_path": str(output_file)
                    }
                    with output_file.open('w') as f:
                        json.dump(scan_result_summary, f, indent=2)
                    
                    logging.info(f"OpenVAS scan details saved to: {output_file}")
                    state[task_name] = {"completed": True, "output": str(output_file)}
                    # Clean up: Consider deleting task and target if not needed for history in GVM
                    # gmp.delete_task(task_id)
                    # gmp.delete_target(target_id)
                    return output_file

            except Exception as e:
                logging.error(f"OpenVAS/GVM scan process failed: {e}", exc_info=True)
                state[task_name] = {"completed": False, "output": None, "error": str(e)}
                return None
            finally:
                if connection: # Ensure connection is closed if opened
                    connection.disconnect()
        
        # Run the GVM process with an overall timeout
        return await asyncio.wait_for(gvm_process(), timeout=timeout)

    except asyncio.TimeoutError:
        logging.error(f"OpenVAS/GVM scan operation timed out globally after {timeout} seconds.")
        state[task_name] = {"completed": False, "output": None, "error": f"Global timeout after {timeout}s"}
        return None
    except Exception as e: # Catch any other unexpected errors
        logging.error(f"An unexpected error occurred in OpenVAS scan wrapper: {e}", exc_info=True)
        state[task_name] = {"completed": False, "output": None, "error": f"Unexpected GVM wrapper error: {e}"}
        return None


async def analyze_urls_for_xss(
    urls_file: Path,
    output_dir: Path,
    dalfox_path: str,
    state: dict,
    rate_limit: int, # Dalfox uses --rate-limit for requests per second
    timeout: int = 600, # Overall timeout for dalfox process
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Analyze URLs for XSS vulnerabilities with Dalfox."""
    config_data = load_config(config_path)
    task_name = "analyze_urls_for_xss"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.exists(): # Assuming urls_file contains URLs to test
        logging.error(f"URLs file for Dalfox not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running XSS scan with Dalfox on {urls_file}")
    output_file = output_dir / "xss_dalfox_results.json" # Changed to JSON for structured output
    
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file), 
        "--output", str(output_file), # Use --output for file saving
        "--format", "json", # Specify JSON output format
        "--rate-limit", str(rate_limit)
    ]
    dalfox_cmd.extend(config_data.get('dalfox_common_options_list', []))
    # Blind XSS URL if configured globally (passed as bxss_url to other functions)
    if config_data.get('bxss_url'):
        dalfox_cmd.extend(["--blind", config_data['bxss_url']])

    try:
        # Dalfox has its own retry/timeout mechanisms internally often.
        # The loop here is for script-level retries if dalfox itself fails completely.
        for attempt in range(1): # Reduced script-level retries, rely on Dalfox
            await run_cmd(dalfox_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"XSS scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Dalfox attempt {attempt + 1} did not produce output, retrying if configured...")
            if attempt < 0: # No retries unless value > 0
                 await asyncio.sleep(config_data['dalfox_retry_delay_seconds'])
        
        logging.info("No XSS vulnerabilities found by Dalfox or Dalfox process issue.")
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
    bxss_url: str, # Passed directly, could also be from config_data['bxss_url']
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Analyze URLs for DOM-based XSS vulnerabilities using Dalfox."""
    config_data = load_config(config_path)
    task_name = "analyze_urls_for_domxss"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file for Dalfox DOM XSS not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running DOM XSS scan with Dalfox on: {urls_file}")
    output_file = output_dir / "domxss_dalfox_results.json" # Changed to JSON
    
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file),
        "--output", str(output_file),
        "--format", "json",
        "--rate-limit", str(rate_limit)
    ]
    dalfox_cmd.extend(config_data.get('dalfox_dom_options_list', [])) # Uses DOM specific options
    
    # Use passed bxss_url or fallback to global config if passed one is empty
    current_bxss_url = bxss_url if bxss_url else config_data.get('bxss_url')
    if current_bxss_url:
        dalfox_cmd.extend(["--blind", current_bxss_url])
    
    try:
        for attempt in range(1): # Reduced retries
            await run_cmd(dalfox_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"DOM XSS scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Dalfox DOM XSS attempt {attempt + 1} failed, retrying if configured...")
            if attempt < 0:
                 await asyncio.sleep(config_data['dalfox_retry_delay_seconds'])
        
        logging.info("No DOM XSS vulnerabilities found or Dalfox DOM XSS failed.")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Dalfox DOM XSS scan timed out after {timeout} seconds")
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
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Perform advanced XSS checks on URLs with XSS-prone parameters."""
    config_data = load_config(config_path)
    task_name = "check_xss_advanced"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file for Advanced XSS not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running advanced XSS checks with Dalfox from: {urls_file}")
    output_file = output_dir / "advanced_xss_dalfox_results.json"

    xss_params_regex_str = config_data.get('xss_prone_parameters_regex', '')
    all_urls_from_file = read_file_lines_or_empty(urls_file)
    
    filtered_urls_for_dalfox = []
    if xss_params_regex_str:
        try:
            xss_params_regex = re.compile(xss_params_regex_str, re.IGNORECASE)
            filtered_urls_for_dalfox = [
                url for url in all_urls_from_file if xss_params_regex.search(url)
            ]
        except re.error as re_err:
            logging.error(f"Invalid XSS prone parameters regex in config: {re_err}")
            filtered_urls_for_dalfox = all_urls_from_file 
    else:
        filtered_urls_for_dalfox = all_urls_from_file

    if not filtered_urls_for_dalfox:
        logging.info("No URLs (after filtering for XSS-prone parameters) found for advanced Dalfox scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    temp_filtered_urls_file = output_dir / "temp_advanced_xss_urls.txt"
    with temp_filtered_urls_file.open('w') as f:
        for url in filtered_urls_for_dalfox:
            f.write(url + '\n')

    dalfox_cmd = [
        dalfox_path, "file", str(temp_filtered_urls_file), 
        "--output", str(output_file),
        "--format", "json",
        "--rate-limit", str(rate_limit)
    ]
    dalfox_cmd.extend(config_data.get('dalfox_common_options_list', []))
    current_bxss_url = bxss_url if bxss_url else config_data.get('bxss_url')
    if current_bxss_url:
        dalfox_cmd.extend(["--blind", current_bxss_url])
    
    try:
        for attempt in range(1):  # Reduced retries
            await run_cmd(dalfox_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"Advanced XSS analysis completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Dalfox advanced XSS attempt {attempt + 1} failed, retrying if configured...")
            if attempt < 0:
                await asyncio.sleep(config_data['dalfox_retry_delay_seconds'])
        
        logging.info("No advanced XSS vulnerabilities found by Dalfox.")
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
    finally:
        temp_filtered_urls_file.unlink(missing_ok=True)  # Ensure cleanup
