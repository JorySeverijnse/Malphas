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

async def dnsrecon_scan(
    domain: str,
    output_dir: Path,
    dnsrecon_path: str,
    state: dict,
    rate_limit: int,
    dns_wordlist: str,
    timeout: int = 600
) -> Optional[Path]:
    """Run DNS enumeration using dnsrecon with a specified wordlist.

    Args:
        domain: Target domain for enumeration.
        output_dir: Directory to store output files.
        dnsrecon_path: Path to dnsrecon binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        dns_wordlist: Path to DNS wordlist for brute-forcing.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If dnsrecon_path or dns_wordlist does not exist.
    """
    task_name = "dnsrecon_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    # Validate inputs
    if not Path(dnsrecon_path).is_file():
        logging.error(f"DNSRecon binary not found: {dnsrecon_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dnsrecon_path}"}
        return None
    if not Path(dns_wordlist).is_file():
        logging.error(f"DNS wordlist not found: {dns_wordlist}")
        state[task_name] = {"completed": False, "output": None, "error": f"Wordlist not found: {dns_wordlist}"}
        return None

    logging.debug(f"Running DNS enumeration for domain: {domain}")
    output_file = output_dir / "dnsrecon.json"
    cmd = [
        dnsrecon_path, "-d", domain, "-t", "std,brt",
        "--lifetime", "10", "-j", str(output_file),
        "-D", dns_wordlist
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
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
    except asyncio.TimeoutError:
        logging.error(f"DNSRecon timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"DNSRecon command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"DNSRecon failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def subfinder_enum(
    domain: str,
    output_dir: Path,
    subfinder_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Enumerate subdomains using subfinder.

    Args:
        domain: Target domain for enumeration.
        output_dir: Directory to store output files.
        subfinder_path: Path to subfinder binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If subfinder_path does not exist.
    """
    task_name = "subfinder_enum"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(subfinder_path).is_file():
        logging.error(f"Subfinder binary not found: {subfinder_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {subfinder_path}"}
        return None

    logging.debug(f"Starting subdomain enumeration for domain: {domain}")
    output_file = output_dir / "subdomains_subfinder.txt"
    cmd = [
        subfinder_path, "-d", domain, "-silent", "-all",
        "-recursive", "-nW", "-o", str(output_file),
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Subdomain enumeration completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No subdomains found or subfinder failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Subfinder timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Subfinder command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Subfinder failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def amass_enum(
    domain: str,
    output_dir: Path,
    amass_path: str,
    state: dict,
    active: bool = False,
    rate_limit: int = 50,
    timeout: int = 1800
) -> Optional[Path]:
    """Enumerate subdomains using Amass.

    Args:
        domain: Target domain for enumeration.
        output_dir: Directory to store output files.
        amass_path: Path to Amass binary.
        state: Dictionary to track task state.
        active: Whether to perform active enumeration (default: False).
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 1800).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If amass_path does not exist.
    """
    task_name = "amass_enum"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(amass_path).is_file():
        logging.error(f"Amass binary not found: {amass_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {amass_path}"}
        return None

    logging.debug(f"Running Amass subdomain enumeration for domain: {domain}")
    output_file = output_dir / "subdomains_amass.txt"
    cmd = [amass_path, "enum", "-d", domain, "-o", str(output_file), "-silent"]
    if not active:
        cmd.append("-passive")
    cmd.extend(["-rps", str(rate_limit)])
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Amass subdomain enumeration completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No subdomains found or amass failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Amass timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Amass command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Amass failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def httpx_probe(
    subdomains_file: Path,
    output_dir: Path,
    httpx_path: str,
    state: dict,
    rate_limit: int,
    threads: Optional[int] = None,
    timeout: int = 600
) -> Optional[Path]:
    """Probe live hosts using httpx.

    Args:
        subdomains_file: File containing subdomains to probe.
        output_dir: Directory to store output files.
        httpx_path: Path to httpx binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        threads: Number of concurrent threads (default: calculated based on subdomains).
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If httpx_path or subdomains_file does not exist.
    """
    task_name = "httpx_probe"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not subdomains_file.is_file():
        logging.error(f"Subdomains file not found: {subdomains_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {subdomains_file}"}
        return None

    logging.debug(f"Probing live hosts from: {subdomains_file}")
    output_file = output_dir / "live_hosts_httpx.txt"
    subdomains = read_file_lines_or_empty(subdomains_file)
    if not threads:
        threads = min(100, max(10, len(subdomains) // 2))  # More conservative thread calculation
    cmd = [
        httpx_path, "-l", str(subdomains_file), "-silent", "-o", str(output_file),
        "-threads", str(threads), "-timeout", "15", "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Live hosts probing completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No live hosts found or httpx failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Httpx timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Httpx failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def shodan_scan(
    domain: str,
    live_hosts_file: Path,
    output_dir: Path,
    shodan_path: str,
    shodan_api_key: str,
    state: dict,
    rate_limit: int,
    timeout: int = 300
) -> Optional[Path]:
    """Scan hosts using Shodan API.

    Args:
        domain: Target domain for scanning.
        live_hosts_file: File containing live hosts.
        output_dir: Directory to store output files.
        shodan_path: Path to Shodan CLI binary.
        shodan_api_key: Shodan API key.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 300).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If shodan_path or live_hosts_file does not exist.
    """
    task_name = "shodan_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(shodan_path).is_file():
        logging.error(f"Shodan binary not found: {shodan_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {shodan_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not shodan_api_key:
        logging.warning("SHODAN_API_KEY not set. Skipping Shodan scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.debug(f"Running Shodan scan for domain: {domain}")
    output_file = output_dir / "shodan_results.json"
    
    init_cmd = [shodan_path, "init", "<masked>"]  # Mask API key in logs
    try:
        init_output = await run_cmd([shodan_path, "init", shodan_api_key], timeout=30)
        if not init_output or "successfully initialized" not in init_output.lower():
            logging.error("Failed to initialize Shodan API key")
            state[task_name] = {"completed": False, "output": None, "error": "Shodan init failed"}
            return None
    except asyncio.TimeoutError:
        logging.error("Shodan init timed out after 30 seconds")
        state[task_name] = {"completed": False, "output": None, "error": "Timeout after 30s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Shodan init command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Shodan init failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    info_cmd = [shodan_path, "info"]
    try:
        info_output = await run_cmd(info_cmd, timeout=30)
        if not info_output:
            logging.error("Shodan info command failed")
            state[task_name] = {"completed": False, "output": None, "error": "Shodan info failed"}
            return None
        
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
    except asyncio.TimeoutError:
        logging.error("Shodan info timed out after 30 seconds")
        state[task_name] = {"completed": False, "output": None, "error": "Timeout after 30s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Shodan info command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Shodan info failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    
    search_query = f"hostname:{domain}"
    cmd = [
        shodan_path, "search", "--fields", "ip_str,port,org,os,hostnames",
        "--limit", "100", search_query
    ]
    try:
        await run_cmd(cmd, output_file=output_file, timeout=timeout)
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
    except asyncio.TimeoutError:
        logging.error(f"Shodan search timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Shodan search command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Shodan search failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def naabu_scan(
    subdomains_file: Path,
    output_dir: Path,
    naabu_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Scan ports using Naabu.

    Args:
        subdomains_file: File containing subdomains to scan.
        output_dir: Directory to store output files.
        naabu_path: Path to Naabu binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If naabu_path or subdomains_file does not exist.
    """
    task_name = "naabu_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(naabu_path).is_file():
        logging.error(f"Naabu binary not found: {naabu_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {naabu_path}"}
        return None
    if not subdomains_file.is_file():
        logging.error(f"Subdomains file not found: {subdomains_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {subdomains_file}"}
        return None

    logging.debug(f"Scanning ports from: {subdomains_file}")
    output_file = output_dir / "ports_naabu.txt"
    cmd = [
        naabu_path, "-l", str(subdomains_file), "-silent", "-o", str(output_file),
        "-rate", str(rate_limit), "-top-ports", "1000"
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Port scanning completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No ports found or naabu failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Naabu timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Naabu command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Naabu failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def nuclei_scan_network(
    live_hosts_file: Path,
    output_dir: Path,
    nuclei_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Scan for network vulnerabilities using Nuclei.

    Args:
        live_hosts_file: File containing live hosts to scan.
        output_dir: Directory to store output files.
        nuclei_path: Path to Nuclei binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If nuclei_path or live_hosts_file does not exist.
    """
    task_name = "nuclei_scan_network"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(nuclei_path).is_file():
        logging.error(f"Nuclei binary not found: {nuclei_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {nuclei_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None

    logging.debug(f"Running network vulnerability scan from: {live_hosts_file}")
    output_file = output_dir / "vulnerabilities_network_nuclei.txt"
    cmd = [
        nuclei_path, "-l", str(live_hosts_file), "-t", "nuclei-templates/network",
        "-severity", "low,medium,high,critical", "-silent", "-o", str(output_file),
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Network vulnerability scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No network vulnerabilities found or nuclei failed")
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
    lfi_payloads: List[str],
    timeout: int = 600
) -> Optional[Path]:
    """Check for Local File Inclusion (LFI) vulnerabilities.

    Args:
        live_hosts_file: File containing live hosts to scan.
        output_dir: Directory to store output files.
        httpx_path: Path to httpx binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        lfi_payloads: List of LFI payloads to test.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If httpx_path or live_hosts_file does not exist.
        ValueError: If lfi_payloads is empty.
    """
    task_name = "check_lfi"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not lfi_payloads:
        logging.error("No LFI payloads provided")
        state[task_name] = {"completed": False, "output": None, "error": "No LFI payloads provided"}
        return None

    logging.debug(f"Checking LFI from: {live_hosts_file}")
    output_file = output_dir / "lfi_httpx.txt"
    cmd = [
        httpx_path, "-l", str(live_hosts_file), "-silent", "-path", ",".join(lfi_payloads),
        "-o", str(output_file), "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"LFI check completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No LFI vulnerabilities found or httpx failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"LFI check timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"LFI check failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def cms_checks(
    live_hosts_file: Path,
    output_dir: Path,
    httpx_path: str,
    wpscan_path: str,
    wpscan_api_token: str,
    state: dict,
    rate_limit: int,
    cms_paths: List[str],
    timeout: int = 600
) -> Optional[Path]:
    """Check for CMS vulnerabilities and perform WPScan if WordPress is detected.

    Args:
        live_hosts_file: File containing live hosts to scan.
        output_dir: Directory to store output files.
        httpx_path: Path to httpx binary.
        wpscan_path: Path to WPScan binary.
        wpscan_api_token: WPScan API token (optional).
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        cms_paths: List of CMS paths to check.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If httpx_path, wpscan_path, or live_hosts_file does not exist.
        ValueError: If cms_paths is empty.
    """
    task_name = "cms_checks"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

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
    if not cms_paths:
        logging.error("No CMS paths provided")
        state[task_name] = {"completed": False, "output": None, "error": "No CMS paths provided"}
        return None

    logging.debug(f"Checking CMS vulnerabilities from: {live_hosts_file}")
    output_file = output_dir / "cms_vulns.txt"
    wordpress_output = output_dir / "wp_vulns_wpscan.txt"
    
    cmd = [
        httpx_path, "-l", str(live_hosts_file), "-silent", "-path", ",".join(cms_paths),
        "-sc", "-cl", "-o", str(output_file), "-rl", str(rate_limit)
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
                wpscan_cmd.extend(["--api-token", "<masked>"])  # Mask API token in logs
            try:
                await run_cmd(wpscan_cmd, timeout=timeout)
            except asyncio.TimeoutError:
                logging.error(f"WPScan timed out after {timeout} seconds")
            except FileNotFoundError as e:
                logging.error(f"WPScan command not found: {e}")
            except Exception as e:
                logging.error(f"WPScan failed: {e}")
    
    if output_file.exists() or wordpress_output.exists():
        logging.debug(f"CMS checks completed, output: {output_file}, WPScan: {wordpress_output if wordpress_detected else 'N/A'}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.debug("No CMS vulnerabilities found or checks failed")
    state[task_name] = {"completed": True, "output": None}
    return None

async def fetch_urls_wayback(
    domain: str,
    output_dir: Path,
    waybackurls_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Fetch URLs from Wayback Machine.

    Args:
        domain: Target domain for URL fetching.
        output_dir: Directory to store output files.
        waybackurls_path: Path to waybackurls binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If waybackurls_path does not exist.
    """
    task_name = "fetch_urls_wayback"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(waybackurls_path).is_file():
        logging.error(f"Waybackurls binary not found: {waybackurls_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {waybackurls_path}"}
        return None

    logging.debug(f"Fetching URLs for domain: {domain}")
    output_file = output_dir / "urls_wayback.txt"
    wayback_cmd = [waybackurls_path, domain]
    try:
        wayback_urls = await run_cmd(wayback_cmd, timeout=timeout)
        if wayback_urls:
            with output_file.open('w') as f:
                f.write(wayback_urls + '\n')
            logging.debug(f"URL fetching completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No URLs found or waybackurls failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Waybackurls timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Waybackurls command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Waybackurls failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def gospider_crawl(
    domain: str,
    output_dir: Path,
    gospider_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Crawl URLs using GoSpider.

    Args:
        domain: Target domain for crawling.
        output_dir: Directory to store output files.
        gospider_path: Path to GoSpider binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If gospider_path does not exist.
    """
    task_name = "gospider_crawl"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(gospider_path).is_file():
        logging.error(f"GoSpider binary not found: {gospider_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {gospider_path}"}
        return None

    logging.debug(f"Crawling URLs for domain: {domain}")
    output_file = output_dir / "urls_gospider.txt"
    cmd = [
        gospider_path, "-s", f"https://{domain}", "-o", str(output_file),
        "-d", "3", "--robots", "--sitemap", "--other-source",
        "-r", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"URL crawling completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No URLs found or gospider failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"GoSpider timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"GoSpider command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Gospider failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def detect_login_portals(
    urls_file: Path,
    output_dir: Path,
    httpx_path: str,
    state: dict,
    rate_limit: int,
    login_paths: List[str],
    timeout: int = 600
) -> Optional[Path]:
    """Detect login portals from URLs.

    Args:
        urls_file: File containing URLs to check.
        output_dir: Directory to store output files.
        httpx_path: Path to httpx binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        login_paths: List of login paths to check.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If httpx_path or urls_file does not exist.
        ValueError: If login_paths is empty.
    """
    task_name = "detect_login_portals"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None
    if not login_paths:
        logging.error("No login paths provided")
        state[task_name] = {"completed": False, "output": None, "error": "No login paths provided"}
        return None

    logging.debug(f"Detecting login portals from: {urls_file}")
    output_file = output_dir / "login_portals.txt"
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
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Login portal detection completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No live login portals found or httpx failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Login portal detection timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Login portal detection failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
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
    """Scan for SQL injection vulnerabilities using SQLMap.

    Args:
        login_file: File containing login URLs to scan.
        output_dir: Directory to store output files.
        sqlmap_path: Path to SQLMap binary.
        state: Dictionary to track task state.
        level: SQLMap scan level (1-5, default: 2).
        risk: SQLMap risk level (1-3, default: 2).
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If sqlmap_path or login_file does not exist.
        ValueError: If level or risk is out of valid range.
    """
    task_name = "sqlmap_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(sqlmap_path).is_file():
        logging.error(f"SQLMap binary not found: {sqlmap_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {sqlmap_path}"}
        return None
    if not login_file.is_file():
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

    logging.debug(f"Running SQLMap on: {login_file}")
    output_file = output_dir / "sqlmap_vulns.txt"
    cmd = [
        sqlmap_path, "-m", str(login_file), "--batch", "--level", str(level),
        "--risk", str(risk), "--forms", "-o", str(output_file)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"SQLMap scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No SQLi vulnerabilities found or sqlmap failed")
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
    live_hosts_file: Path,
    output_dir: Path,
    curl_path: str,
    zap_api_url: str,
    zap_api_key: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Run OWASP ZAP spider scan on live hosts.

    Args:
        live_hosts_file: File containing live hosts to scan.
        output_dir: Directory to store output files.
        curl_path: Path to curl binary.
        zap_api_url: URL of the ZAP API.
        zap_api_key: ZAP API key.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If curl_path or live_hosts_file does not exist.
    """
    task_name = "zap_spider_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(curl_path).is_file():
        logging.error(f"Curl binary not found: {curl_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {curl_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not zap_api_key:
        logging.warning("ZAP_API_KEY not set in config.ini. Skipping OWASP ZAP scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.debug(f"Running OWASP ZAP spider scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "zap_spider.json"
    
    check_cmd = [curl_path, "-s", zap_api_url]
    try:
        check_output = await run_cmd(check_cmd, timeout=30)
        if not check_output or "ZAP" not in check_output:
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
            f"{zap_api_url}/JSON/spider/action/scan/?url={target_url}&apikey=<masked>&maxChildren=10"
        ]
        try:
            zap_output = await run_cmd([curl_path, "-s", f"{zap_api_url}/JSON/spider/action/scan/?url={target_url}&apikey={zap_api_key}&maxChildren=10"], timeout=timeout)
            if zap_output:
                results.append({"url": target_url, "output": zap_output})
        except asyncio.TimeoutError:
            logging.error(f"ZAP scan for {target_url} timed out after {timeout} seconds")
        except FileNotFoundError as e:
            logging.error(f"Curl command not found: {e}")
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

async def openvas_scan(
    live_hosts_file: Path,
    output_dir: Path,
    username: str,
    password: str,
    state: dict,
    timeout: int = 3600
) -> Optional[Path]:
    """Run OpenVAS scan on live hosts.

    Args:
        live_hosts_file: File containing live hosts to scan.
        output_dir: Directory to store output files.
        username: OpenVAS username.
        password: OpenVAS password.
        state: Dictionary to track task state.
        timeout: Command execution timeout in seconds (default: 3600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If live_hosts_file does not exist.
    """
    task_name = "openvas_scan"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not username or not password:
        logging.warning("OPENVAS_USERNAME or OPENVAS_PASSWORD not set in config.ini. Skipping OpenVAS scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.debug(f"Running OpenVAS scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "openvas_scan.json"
    
    hosts = read_file_lines_or_empty(live_hosts_file)
    if not hosts:
        logging.warning("No live hosts available for OpenVAS scan. Skipping.")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    for attempt in range(3):
        try:
            connection = SSHConnection(hostname="localhost", username=username, password="<masked>")
            with Gmp(connection) as gmp:
                gmp.authenticate(username, "<masked>")
                
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
        except asyncio.TimeoutError:
            logging.error(f"OpenVAS scan timed out after {timeout} seconds")
            if attempt < 2:
                await asyncio.sleep(5)
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
    """Analyze URLs for XSS vulnerabilities using Dalfox.

    Args:
        urls_file: File containing URLs to scan.
        output_dir: Directory to store output files.
        dalfox_path: Path to Dalfox binary.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If dalfox_path or urls_file does not exist.
    """
    task_name = "analyze_urls_for_xss"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.debug(f"Analyzing URLs for XSS from: {urls_file}")
    output_file = output_dir / "xss_dalfox.txt"
    dalfox_cmd = [
        dalfox_path, "file", str(urls_file), "-o", str(output_file),
        "--waf-bypass", "--rate-limit", str(rate_limit)
    ]
    try:
        await run_cmd(dalfox_cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"XSS analysis completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No XSS vulnerabilities found or dalfox failed")
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
        logging.error(f"Dalfox XSS scan failed: {e}")
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
    """Analyze URLs for DOM-based XSS vulnerabilities using Dalfox.

    Args:
        urls_file: File containing URLs to scan.
        output_dir: Directory to store output files.
        dalfox_path: Path to Dalfox binary.
        bxss_url: Blind XSS URL for testing.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If dalfox_path or urls_file does not exist.
    """
    task_name = "analyze_urls_for_domxss"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

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
        await run_cmd(dalfox_cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"DOM XSS analysis completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No DOM XSS vulnerabilities found or dalfox failed")
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
    timeout: int = 600
) -> Optional[Path]:
    """Perform advanced XSS checks on URLs with XSS-prone parameters.

    Args:
        urls_file: File containing URLs to scan.
        output_dir: Directory to store output files.
        dalfox_path: Path to Dalfox binary.
        bxss_url: Blind XSS URL for testing.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If dalfox_path or urls_file does not exist.
    """
    task_name = "check_xss_advanced"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(dalfox_path).is_file():
        logging.error(f"Dalfox binary not found: {dalfox_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {dalfox_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

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
        await run_cmd(dalfox_cmd, timeout=timeout)
        if output_file.exists():
            logging.debug(f"Advanced XSS analysis completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.debug("No advanced XSS vulnerabilities found")
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

async def check_open_redirects(
    urls_file: Path,
    output_dir: Path,
    curl_path: str,
    redirect_url: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Check for open redirect vulnerabilities.

    Args:
        urls_file: File containing URLs to scan.
        output_dir: Directory to store output files.
        curl_path: Path to curl binary.
        redirect_url: URL to test for redirects.
        state: Dictionary to track task state.
        rate_limit: Rate limit for requests per second.
        timeout: Command execution timeout in seconds (default: 600).

    Returns:
        Path to output file if successful, None otherwise.

    Raises:
        FileNotFoundError: If curl_path or urls_file does not exist.
    """
    task_name = "check_open_redirects"
    if state.get(task_name, {}).get("completed"):
        logging.debug(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(curl_path).is_file():
        logging.error(f"Curl binary not found: {curl_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {curl_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.debug(f"Checking open redirects from: {urls_file}")
    output_file = output_dir / "open_redirects.txt"
    
    urls = read_file_lines_or_empty(urls_file)
    filtered_urls = [url for url in urls if re.search(r'=http', url, re.IGNORECASE)]
    if not filtered_urls:
        logging.debug("No URLs with =http found")
        state[task_name] = {"completed":
