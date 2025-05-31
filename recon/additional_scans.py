import asyncio
import logging
import json
from pathlib import Path
from typing import Optional
from ..utils import run_cmd, read_file_lines_or_empty # Assuming run_cmd is compatible with list of strings
from ..config import load_config # Added import

async def check_sqli_nuclei(
    subdomains_file: Path,
    urls_file: Path,
    output_dir: Path,
    httpx_path: str,
    nuclei_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Check for SQL injection vulnerabilities using Nuclei."""
    config_data = load_config(config_path) # Load config
    task_name = "check_sqli_nuclei"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {httpx_path}"}
        return None
    if not Path(nuclei_path).is_file():
        logging.error(f"Nuclei binary not found: {nuclei_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {nuclei_path}"}
        return None
    if not subdomains_file.is_file():
        logging.error(f"Subdomains file not found: {subdomains_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {subdomains_file}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Checking SQLi vulnerabilities with Nuclei on: {urls_file}")
    output_file = output_dir / "sqli_nuclei.txt"
    output_file_json = output_dir / "sqli_nuclei.json" 
    temp_file = output_dir / "live_urls_httpx.txt"

    # Probe live URLs with httpx
    httpx_cmd = [
        httpx_path, "-l", str(urls_file), "-silent", "-o", str(temp_file),
        "-threads", str(config_data['httpx_common_threads']), 
        "-timeout", str(config_data['httpx_flag_timeout']), 
        "-rl", str(rate_limit),
        "-follow-redirects", "-title", "-tech-detect" 
    ]
    try:
        await run_cmd(httpx_cmd, timeout=timeout)
        if not temp_file.exists() or temp_file.stat().st_size == 0:
            logging.info("No live URLs found for SQLi scan")
            state[task_name] = {"completed": True, "output": None}
            return None
    except Exception as e:
        logging.error(f"Httpx probe failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

    # Run Nuclei with SQLi templates
    nuclei_cmd = [
        nuclei_path, "-l", str(temp_file), 
        "-t", config_data['nuclei_sqli_template_path'],
        "-severity", config_data['nuclei_sqli_severity'], 
        "-silent", "-o", str(output_file),
        "-json", str(output_file_json), 
        "-rl", str(rate_limit), 
        "-timeout", str(config_data['nuclei_common_flag_timeout']), 
        "-retries", str(config_data['nuclei_common_retries'])
    ]
    try:
        # The Python script already has a retry logic. We'll keep the command's retry and potentially remove the script's outer loop if desired.
        for attempt in range(config_data['nuclei_common_retries']): 
            await run_cmd(nuclei_cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"SQLi scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Nuclei SQLi attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(config_data['nuclei_common_retry_delay_seconds'])
        logging.info("No SQLi vulnerabilities found or Nuclei failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Nuclei SQLi scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Nuclei command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Nuclei SQLi scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def nuclei_scan_web(
    urls_file: Path,
    output_dir: Path,
    nuclei_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Scan web URLs for vulnerabilities using Nuclei."""
    config_data = load_config(config_path) # Load config
    task_name = "nuclei_scan_web"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(nuclei_path).is_file():
        logging.error(f"Nuclei binary not found: {nuclei_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {nuclei_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    logging.info(f"Running web vulnerability scan with Nuclei on: {urls_file}")
    output_file = output_dir / "vulnerabilities_web_nuclei.txt"
    output_file_json = output_dir / "vulnerabilities_web_nuclei.json" 

    cmd = [
        nuclei_path, "-l", str(urls_file), 
        "-t", config_data['nuclei_web_template_path'],
        "-severity", config_data['nuclei_web_severity'], 
        "-silent", "-o", str(output_file),
        "-json", str(output_file_json), 
        "-rl", str(rate_limit), 
        "-timeout", str(config_data['nuclei_common_flag_timeout']), 
        "-retries", str(config_data['nuclei_common_retries'])
    ]
    try:
        for attempt in range(config_data['nuclei_common_retries']):
            await run_cmd(cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                logging.info(f"Web vulnerability scan completed, output: {output_file}")
                state[task_name] = {"completed": True, "output": str(output_file)}
                return output_file
            logging.warning(f"Nuclei web attempt {attempt + 1} failed, retrying...")
            await asyncio.sleep(config_data['nuclei_common_retry_delay_seconds'])
        logging.info("No web vulnerabilities found or Nuclei failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Nuclei web scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Nuclei command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Nuclei web scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def js_discovery_katana(
    live_hosts_file: Path,
    output_dir: Path,
    katana_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Discover JavaScript endpoints using Katana."""
    config_data = load_config(config_path) # Load config
    task_name = "js_discovery_katana"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(katana_path).is_file():
        logging.error(f"Katana binary not found: {katana_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {katana_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None

    logging.info(f"Running JavaScript discovery with Katana on: {live_hosts_file}")
    output_file = output_dir / "js_endpoints_katana.txt"
    output_file_json = output_dir / "js_endpoints_katana.json" 

    cmd = [
        katana_path, "-l", str(live_hosts_file), "-o", str(output_file),
        "-json", str(output_file_json), 
        "-js-crawl", "-silent", "-rl", str(rate_limit),
        "-c", str(config_data['katana_js_crawl_concurrency']), 
        "-d", str(config_data['katana_js_crawl_depth'])
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists() and output_file.stat().st_size > 0:
            logging.info(f"JavaScript discovery completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No JavaScript endpoints found or Katana failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Katana scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Katana command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Katana scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def fuzz_endpoints_ffuf(
    js_endpoints_file: Path,
    output_dir: Path,
    ffuf_path: str,
    state: dict,
    wordlist: str,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Fuzz endpoints using FFUF."""
    config_data = load_config(config_path) # Load config
    task_name = "fuzz_endpoints_ffuf"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(ffuf_path).is_file():
        logging.error(f"FFUF binary not found: {ffuf_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"Binary not found: {ffuf_path}"}
        return None
    if not Path(wordlist).is_file(): # Wordlist is passed as parameter, already configurable by caller
        logging.error(f"Wordlist not found: {wordlist}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {wordlist}"}
        return None
    if not js_endpoints_file.is_file():
        logging.error(f"JS endpoints file not found: {js_endpoints_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {js_endpoints_file}"}
        return None

    logging.info(f"Fuzzing endpoints with FFUF on: {js_endpoints_file}")
    output_file = output_dir / "fuzz_ffuf.txt"
    output_file_json = output_dir / "fuzz_ffuf.json"

    cmd = [
        ffuf_path, "-u", "FUZZ", "-w", str(wordlist), "-o", str(output_file),
        "-json", str(output_file_json), 
        "-l", str(js_endpoints_file), "-silent", "-rl", str(rate_limit),
        "-t", str(config_data['ffuf_threads']), 
        "-mc", config_data['ffuf_match_codes'], 
        "-ms", config_data['ffuf_match_size'], 
        "-fc", config_data['ffuf_filter_codes'], 
        "-follow-redirects" 
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists() and output_file.stat().st_size > 0:
            logging.info(f"Endpoint fuzzing completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No endpoints found or FFUF failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"FFUF scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"FFUF command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"FFUF scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def github_secrets_trufflehog(
    domain: str,
    output_dir: Path,
    trufflehog_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Scan for secrets in GitHub repositories using TruffleHog."""
    config_data = load_config(config_path)
    task_name = "github_secrets_trufflehog"

    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name]["output"] else None

    if not Path(trufflehog_path).is_file():
        error = f"TruffleHog binary not found: {trufflehog_path}"
        logging.error(error)
        state[task_name] = {"completed": False, "output": None, "error": error}
        return None

    github_org_name = domain
    output_file = output_dir / "trufflehog_secrets.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        trufflehog_path, "github",
        "--org", github_org_name,
        "--json",
        "--concurrency", str(rate_limit),
        "--max-depth", str(config_data["trufflehog_max_depth"])
    ]

    logging.info(f"Running TruffleHog: {' '.join(cmd)}")

    try:
        with output_file.open("w") as f:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=f,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise

        if process.returncode != 0:
            error_msg = stderr.decode().strip() if stderr else "Unknown error"
            logging.error(f"TruffleHog failed: {error_msg}")
            state[task_name] = {"completed": False, "output": None, "error": error_msg}
            return None

        if output_file.exists() and output_file.stat().st_size > 0:
            logging.info(f"GitHub secrets scan completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        else:
            logging.info("No secrets found.")
            state[task_name] = {"completed": True, "output": None}
            return None

    except asyncio.TimeoutError:
        logging.error(f"TruffleHog scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except Exception as e:
        logging.error(f"TruffleHog scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

