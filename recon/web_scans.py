import asyncio
import logging
import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse # For open redirect
from ..utils import run_cmd, read_file_lines_or_empty
from ..config import load_config # Added import

async def fetch_urls_wayback(
    domain: str,
    output_dir: Path,
    waybackurls_path: str,
    state: dict,
    rate_limit: int, # Waybackurls doesn't have a rate-limit flag usually. Kept for consistency.
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path (not used for cmd params here)
) -> Optional[Path]:
    """Fetch URLs from Wayback Machine."""
    # config_data = load_config(config_path) # Not used for new cmd params in this func
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
    # Waybackurls basic command, can add --no-subs if needed via config
    wayback_cmd = [waybackurls_path, domain] 
    try:
        # run_cmd returns a string which is the stdout
        wayback_output_str = await run_cmd(wayback_cmd, timeout=timeout)
        if wayback_output_str and wayback_output_str.strip(): # Check if not empty
            with output_file.open('w') as f:
                f.write(wayback_output_str.strip() + '\n') # Ensure clean output
            logging.info(f"URL fetching completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        
        logging.info("No URLs found by waybackurls or waybackurls produced empty output.")
        state[task_name] = {"completed": True, "output": None} # Success if no URLs
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
    rate_limit: float, # Gospider uses -t for threads, -c for concurrent, -r for request delay.
                       # The 'rate_limit' param is used for '-r' in current script.
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Crawl URLs using GoSpider."""
    config_data = load_config(config_path) # Load config
    task_name = "gospider_crawl"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(gospider_path).is_file():
        logging.error(f"GoSpider binary not found: {gospider_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {gospider_path}"}
        return None

    logging.info(f"Crawling URLs for domain: {domain} with GoSpider")
    # Gospider outputs to a folder specified by -o, containing files like output.txt, urls.txt etc.
    # The original script expects `urls_gospider.txt`. Gospider might create this inside the folder.
    # Let's have gospider output to a specific file if possible, or adjust expectations.
    # Gospider's -o is an output folder. Inside it, it creates files.
    # `gospider -s http://example.com -o output_folder` will create `output_folder/http___example.com.txt`
    # For simplicity, let's keep the original file name, Gospider might handle `output_dir / "urls_gospider.txt"` as a folder.
    # Or, better, Gospider has `-O` (capital O) for a single output file of URLs.
    
    output_file_path = output_dir / "urls_gospider.txt" # This will be the direct output file for URLs

    cmd = [
        gospider_path, "-s", f"https://{domain}", # Assuming https, could be http/https probe first
        "-O", str(output_file_path), # Use -O for single file URL output
        "-d", str(config_data['gospider_depth']),
        # -r is delay between requests in milliseconds, rate_limit here is float, ensure conversion.
        # If rate_limit is intended as "requests per second", then delay is 1000/rate_limit.
        # Original script uses -r str(rate_limit), implies rate_limit *is* the delay in ms.
        # Let's assume rate_limit parameter is the delay in ms for gospider's -r.
        "-r", str(int(rate_limit)) if isinstance(rate_limit, float) else str(rate_limit) 
    ]
    cmd.extend(config_data.get('gospider_flags_list', [])) # Adds --robots, --sitemap etc.

    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file_path.exists() and output_file_path.stat().st_size > 0: # Check size
            logging.info(f"GoSpider URL crawling completed, output: {output_file_path}")
            state[task_name] = {"completed": True, "output": str(output_file_path)}
            return output_file_path
        
        logging.info(f"No URLs found by GoSpider or GoSpider failed to write to {output_file_path}")
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
    urls_file: Path, # File containing many URLs to check
    output_dir: Path,
    httpx_path: str,
    state: dict,
    rate_limit: int,
    login_paths: Optional[List[str]] = None, # Loaded from config if None
    config_path: str = "config.ini",
    timeout: int = 600
) -> Optional[Path]:
    """Detect login portals from a list of URLs by checking for common login paths."""
    config_data = load_config(config_path)
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

    current_login_paths = login_paths if login_paths is not None else config_data.get("login_paths", [])
    if not current_login_paths:
        logging.warning("No login paths provided or found in config. Skipping login portal detection.")
        state[task_name] = {"completed": True, "output": None} # Not an error, just no paths
        return None

    logging.info(f"Detecting login portals from URLs in: {urls_file} using paths: {current_login_paths[:3]}...")
    
    # httpx can take a list of paths with -path flag, separated by comma.
    # It will probe each URL from -l against each path from -path.
    # The output will be URLs that responded.
    
    output_file = output_dir / "login_portals_httpx.txt"
    
    cmd = [
        httpx_path, "-l", str(urls_file),
        "-path", ",".join(current_login_paths), # Probe all login paths for each URL
        "-silent", 
        "-sc", # Show status codes
        "-o", str(output_file),
        "-threads", str(config_data['httpx_login_threads']), 
        "-timeout", str(config_data['httpx_login_flag_timeout']), 
        "-rl", str(rate_limit)
    ]
    # We are interested in 200 OK, but also redirects (301, 302) or forbidden (403) for login pages
    # Add -mc to filter for interesting status codes, e.g. 200,301,302,401,403
    cmd.extend(["-mc", "200,301,302,401,403"])


    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists() and output_file.stat().st_size > 0: # Check size
            logging.info(f"Login portal detection (httpx) completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        
        logging.info("No live login portals found by httpx with specified paths.")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Login portal detection (httpx) timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e: # For httpx
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Login portal detection (httpx) failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None

async def check_open_redirects(
    urls_file: Path, # File containing URLs to check for open redirects
    output_dir: Path,
    curl_path: str, # Curl path
    redirect_url: str, # Malicious URL to redirect to, passed directly (from config originally)
    state: dict,
    rate_limit: int, # Not directly used by curl, more for our script's loop if we had one
    timeout: int = 600, # Overall timeout for the whole function
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Check for open redirect vulnerabilities by modifying URL parameters."""
    config_data = load_config(config_path)
    task_name = "check_open_redirects" # Corrected task name definition
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(curl_path).is_file():
        logging.error(f"Curl binary not found: {curl_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {curl_path}"}
        return None
    if not urls_file.is_file():
        logging.error(f"URLs file for open redirect check not found: {urls_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {urls_file}"}
        return None
    
    current_redirect_url_target = redirect_url if redirect_url else config_data.get('redirect_url')
    if not current_redirect_url_target:
        logging.warning("Target REDIRECT_URL not set/passed. Skipping open redirect scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.info(f"Checking URLs in {urls_file} for open redirects to: {current_redirect_url_target}")
    output_file = output_dir / "open_redirects_found.txt"
    
    all_urls_to_check = read_file_lines_or_empty(urls_file)
    if not all_urls_to_check:
        logging.info("No URLs provided to check for open redirects.")
        state[task_name] = {"completed": True, "output": None}
        return None
        
    current_redirect_params_list = config_data.get('open_redirect_params_list', [])
    curl_output_format = config_data.get('curl_redirect_output_format', "%{http_code} %{url_effective}")
    min_timeout_per_curl = config_data.get('curl_redirect_min_timeout_seconds', 1)

    vulnerable_urls_found = []
    
    # Calculate timeout per curl call, ensuring it's not too short
    # The overall 'timeout' is for the entire function.
    # This means if many URLs, each curl call gets a small fraction.
    # Consider a fixed timeout per curl call instead, or adjust 'timeout' param meaning.
    # For now, let's make timeout per curl call more robust.
    # If timeout is 600s and 100 URLs, each gets 6s.
    # If 1000 URLs, each gets 0.6s, which is too short.
    # Let's set a default timeout per curl command from config, and ensure the overall does not exceed 'timeout'.
    
    # Default timeout for a single curl request, can be overridden if overall timeout is too short for many URLs
    single_curl_timeout = 10 # seconds, reasonable for a single request
    if len(all_urls_to_check) > 0:
        calculated_timeout = timeout // (len(all_urls_to_check) * len(current_redirect_params_list) or 1)
        single_curl_timeout = max(min_timeout_per_curl, calculated_timeout)
        # Cap it also, e.g., not more than 15-20s for a single check to avoid one URL hogging.
        single_curl_timeout = min(single_curl_timeout, 15)


    for original_url_str in all_urls_to_check:
        original_url_str = original_url_str.strip()
        if not original_url_str:
            continue
            
        try:
            parsed_url = urlparse(original_url_str)
            query_params = parse_qs(parsed_url.query)
        except ValueError:
            logging.warning(f"Could not parse URL: {original_url_str}. Skipping for open redirect.")
            continue

        # Try modifying each known redirect parameter
        for param_to_test in current_redirect_params_list:
            # Check if param exists or try adding it (some redirects trigger on any param)
            # For this version, we only modify existing ones.
            if param_to_test in query_params:
                original_param_values = query_params[param_to_test] # Save to restore if needed, though not strictly necessary here
                
                # Create a copy of query_params to modify
                modified_query_params = query_params.copy()
                modified_query_params[param_to_test] = [current_redirect_url_target]
                
                new_query_string = urlencode(modified_query_params, doseq=True)
                # Construct the new URL with the malicious redirect target
                potential_vuln_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params, # Rarely used, but part of spec
                    new_query_string,
                    parsed_url.fragment # Fragment is client-side, usually not part of server request
                ))

                # Now, use curl to see where this new URL actually leads
                curl_cmd = [
                    curl_path, 
                    "-s", # Silent
                    "-L", # Follow redirects (up to a certain limit, default 50)
                    "-I", # Head request (faster, only headers)
                    "--max-time", str(single_curl_timeout), # Max time for this curl operation
                    "--", potential_vuln_url, # -- ensures URL is not mistaken for an option
                    "-o", "/dev/null", # Don't output body
                    "-w", curl_output_format # Output effective URL and HTTP code
                ]
                
                try:
                    # run_cmd returns stdout as a string
                    curl_output_str = await run_cmd(curl_cmd, timeout=single_curl_timeout + 2) # run_cmd timeout slightly > curl's max-time
                    
                    # Example output: "302 https://example.com/"
                    # We need to check if current_redirect_url_target is in the *final* URL.
                    # The -L flag in curl makes %{url_effective} the final URL after redirects.
                    if curl_output_str and current_redirect_url_target in curl_output_str:
                        # More robust check: parse code and effective URL
                        # Assuming format "CODE URL"
                        parts = curl_output_str.strip().split(" ", 1)
                        effective_url_from_curl = parts[1] if len(parts) > 1 else ""
                        
                        if current_redirect_url_target in effective_url_from_curl:
                            logging.info(f"Potential Open Redirect FOUND: {potential_vuln_url} -> led to {effective_url_from_curl}")
                            vulnerable_urls_found.append(f"{potential_vuln_url} (Redirected to: {effective_url_from_curl})")
                            # Break from inner loop (param_to_test) once a vuln is found for this original_url? Or find all params?
                            # Let's find all vulnerable params for a given URL.
                except asyncio.TimeoutError:
                     logging.warning(f"Curl command for {potential_vuln_url} timed out (single_curl_timeout: {single_curl_timeout}s)")
                except Exception as e:
                    logging.warning(f"Failed to check {potential_vuln_url} with curl: {e}")
        
        # Small delay if processing many base URLs to be nice to servers / self
        if len(all_urls_to_check) > 50: await asyncio.sleep(0.1)


    if vulnerable_urls_found:
        with output_file.open('w') as f:
            for vuln_url_info in vulnerable_urls_found:
                f.write(vuln_url_info + '\n')
        logging.info(f"Open redirect check completed. Vulnerable URLs/params saved to: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
        
    logging.info("No open redirect vulnerabilities found with the current checks.")
    state[task_name] = {"completed": True, "output": None}
    return None
