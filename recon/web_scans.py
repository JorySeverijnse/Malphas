# tower/recon/web_scans.py
import asyncio
import logging
import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..utils import run_cmd, read_file_lines_or_empty
from ..config import load_config

async def fetch_urls_wayback(
    domain: str,
    output_dir: Path,
    waybackurls_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Fetch URLs from Wayback Machine."""
    task_name = "fetch_urls_wayback"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(waybackurls_path).is_file():
        logging.error(f"Waybackurls binary not found: {waybackurls_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {waybackurls_path}"}
        return None

    logging.info(f"Fetching URLs for domain: {domain}")
    output_file = output_dir / "urls_wayback.txt"
    wayback_cmd = [waybackurls_path, domain]
    try:
        wayback_urls = await run_cmd(wayback_cmd, timeout=timeout)
        if wayback_urls:
            with output_file.open('w') as f:
                f.write(wayback_urls + '\n')
            logging.info(f"URL fetching completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No URLs found or waybackurls failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Waybackurls scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Waybackurls command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Waybackurls scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def gospider_crawl(
    domain: str,
    output_dir: Path,
    gospider_path: str,
    state: dict,
    rate_limit: float,
    timeout: int = 600
) -> Optional[Path]:
    """Crawl URLs using GoSpider."""
    task_name = "gospider_crawl"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(gospider_path).is_file():
        logging.error(f"GoSpider binary not found: {gospider_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {gospider_path}"}
        return None

    logging.info(f"Crawling URLs for domain: {domain}")
    output_file = output_dir / "urls_gospider.txt"
    cmd = [
        gospider_path, "-s", f"https://{domain}", "-o", str(output_file),
        "-d", "3", "--robots", "--sitemap", "--other-source",
        "-r", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.info(f"URL crawling completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No URLs found or gospider failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"GoSpider scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"GoSpider command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"GoSpider scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def detect_login_portals(
    urls_file: Path,
    output_dir: Path,
    httpx_path: str,
    state: dict,
    rate_limit: int,
    login_paths: Optional[List[str]] = None,
    config_path: str = "config.ini",
    timeout: int = 600
) -> Optional[Path]:
    """Detect login portals from URLs."""
    task_name = "detect_login_portals"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {httpx_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None

    if login_paths is None:
        config = load_config(config_path)
        login_paths = config.get("login_paths", [])
    if not login_paths:
        logging.error("No login paths provided")
        state[task_name] = {"completed": False, "output": None, "error": "No login paths provided"}
        return None

    logging.info(f"Detecting login portals from: {urls_file}")
    output_file = output_dir / "login_portals.txt"
    urls = read_file_lines_or_empty(urls_file)
    login_urls = [url for url in urls if any(path.lower() in url.lower() for path in login_paths)]
    
    if not login_urls:
        logging.info("No login portals found")
        state[task_name] = {"completed": True, "output": None}
        return None
    
    temp_file = output_dir / "login_urls_temp.txt"
    with temp_file.open('w') as f:
        f.write('\n'.join(login_urls) + '\n')
    
    cmd = [
        httpx_path, "-l", str(temp_file),
        "-silent", "-o", str(output_file),
        "-threads", "50", "-timeout", "15", "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
            logging.info(f"Login portal detection completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No live login portals found")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Login portal scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Login portal scan failed: {e}")
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
    """Check for open redirect vulnerabilities."""
    task_name = {"check_open_redirects"}
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(curl_path).is_file():
        logging.error(f"Curl binary not found: {curl_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {curl_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None
    if not redirect_url:
        logging.warning("REDIRECT_URL not set in config.ini. Skipping open redirect scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.info(f"Checking URLs for open redirects: {urls_file}")
    output_file = output_dir / "open_redirects.txt"
    urls = read_file_lines_or_empty(urls_file)
    redirect_params = ["url", "redirect", "next", "dest", "destination", "redirect_uri", "out", "goto"]
    vulnerable_urls = []

    for url in urls:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        modified = False
        for param in redirect_params:
            if param in query_params:
                query_params[param] = [redirect_url]
                modified = True
        if modified:
            new_query = urlencode(query_params, doseq=True)
            new_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            cmd = [
                curl_path, "-s", "-I", "--", new_url,
                "-o", "/dev/null", "-w", "%{http_code} %{url_effective}"
            ]
            try:
                output = await run_cmd(cmd, timeout=timeout // len(urls) or 1)
                if output and redirect_url in output:
                    vulnerable_urls.append(new_url)
            except Exception as e:
                logging.warning(f"Failed to check {new_url} for redirect: {e}")

    if vulnerable_urls:
        with output_file.open('w') as f:
            f.write('\n'.join(vulnerable_urls) + '\n')
        logging.info(f"Open redirect check completed, output: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.info("No open redirect vulnerabilities found")
    state[task_name] = {"completed": True, "output": None}
    return None
