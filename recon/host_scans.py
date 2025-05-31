import asyncio
import logging
import json
from pathlib import Path
from typing import Optional
from ..utils import run_cmd, read_file_lines_or_empty
from ..config import load_config

async def httpx_probe(
    subdomains_file: Path,
    output_dir: Path,
    httpx_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Probe live hosts using httpx."""
    config_data = load_config(config_path)
    task_name = "httpx_probe"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(httpx_path).is_file():
        logging.error(f"Httpx binary not found: {httpx_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {httpx_path}"}
        return None
    if not subdomains_file.is_file():
        logging.error(f"Subdomains file not found: {subdomains_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {subdomains_file}"}
        return None

    logging.info(f"Probing live hosts from: {subdomains_file}")
    output_file = output_dir / "live_hosts_httpx.txt"
    urls_only_file = output_dir / "live_hosts_urls_only.txt"

    cmd = [
        httpx_path, "-l", str(subdomains_file), "-silent", "-o", str(output_file),
        "-threads", str(config_data['httpx_common_threads']),
        "-timeout", str(config_data['httpx_flag_timeout']),
        "-rl", str(rate_limit),
        "-follow-redirects", "-title", "-tech-detect",
        "-sc", "-location", "-server", "-method", "-cname", "-ip", "-websocket", "-efqdn",
        "-json"
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists() and output_file.stat().st_size > 0:
            urls = []
            try:
                with output_file.open('r', encoding='utf-8') as f:
                    lines = f.readlines()
                for line in lines:
                    try:
                        data = json.loads(line.strip())
                        if 'url' in data:
                            urls.append(data['url'])
                    except json.JSONDecodeError:
                        logging.warning(f"Failed to parse JSON line in {output_file}: {line.strip()}")
                        continue
            except IOError as e:
                logging.error(f"Failed to read {output_file}: {e}")
                urls = []

            if urls:
                try:
                    with urls_only_file.open('w', encoding='utf-8') as f:
                        for url in urls:
                            f.write(url + '\n')
                    logging.info(f"Extracted {len(urls)} URLs to {urls_only_file}")
                except IOError as e:
                    logging.error(f"Failed to write to {urls_only_file}: {e}")
                    urls_only_file.unlink(missing_ok=True)
                    state[task_name] = {"completed": True, "output": str(output_file)}
                    return output_file
            else:
                logging.info("No valid URLs extracted from httpx JSON output.")
                urls_only_file.unlink(missing_ok=True)

            logging.info(f"Live host scanning completed, output: {output_file}, URLs only: {urls_only_file}")
            state[task_name] = {"completed": True, "output": str(output_file), "urls_only_output": str(urls_only_file)}
            return output_file
        else:
            logging.info("No live hosts found or httpx failed")
            state[task_name] = {"completed": True, "output": None}
            return None
    except asyncio.TimeoutError:
        logging.error(f"Httpx scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Httpx command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Httpx scan failed: {e}")
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
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Scan hosts using Shodan."""
    task_name = "shodan_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(shodan_path).is_file():
        logging.error(f"Shodan binary not found: {shodan_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {shodan_path}"}
        return None
    if not live_hosts_file.is_file():
        logging.error(f"Live hosts file not found: {live_hosts_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {live_hosts_file}"}
        return None
    if not shodan_api_key:
        logging.warning("SHODAN_API_KEY not set/passed. Skipping Shodan scan.")
        state[task_name] = {"completed": True, "output": None}
        return None

    logging.info(f"Running Shodan scan for hosts in: {live_hosts_file}")
    output_file = output_dir / "shodan_results.json"
    hosts = read_file_lines_or_empty(live_hosts_file)
    results = []

    for host in hosts:
        cmd = [
            shodan_path, "host", host.strip(), "--apikey", shodan_api_key
        ]
        try:
            output_str = await run_cmd(cmd, timeout=timeout)
            if output_str:
                try:
                    json_data = json.loads(output_str)
                    results.append({"host": host.strip(), "data": json_data})
                except json.JSONDecodeError:
                    logging.warning(f"Shodan output for {host.strip()} was not valid JSON. Storing as raw. Output: {output_str[:200]}...")
                    results.append({"host": host.strip(), "data": output_str})
            else:
                logging.info(f"No Shodan output for {host.strip()}")
        except Exception as e:
            logging.warning(f"Shodan scan for {host.strip()} failed: {e}")

    if results:
        with output_file.open('w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"Shodan scan completed, output: {output_file}")
        state[task_name] = {"completed": True, "output": str(output_file)}
        return output_file
    logging.info("No Shodan results found after processing all hosts")
    state[task_name] = {"completed": True, "output": None}
    return None

async def naabu_scan(
    subdomains_file: Path,
    output_dir: Path,
    naabu_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini"
) -> Optional[Path]:
    """Scan for open ports using Naabu."""
    config_data = load_config(config_path)
    task_name = "naabu_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(naabu_path).is_file():
        logging.error(f"Naabu binary not found: {naabu_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {naabu_path}"}
        return None
    if not subdomains_file.is_file():
        logging.error(f"Subdomains file not found: {subdomains_file}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {subdomains_file}"}
        return None

    logging.info(f"Scanning ports from: {subdomains_file}")
    output_file = output_dir / "ports_naabu.txt"
    output_file_json = output_dir / "ports_naabu.json"

    cmd = [
        naabu_path, "-l", str(subdomains_file), "-o", str(output_file),
        "-json", str(output_file_json),
        "-silent", "-rate", str(rate_limit),
        "-p", config_data['naabu_port_range'],
        "-retries", str(config_data['naabu_retries']),
    ]
    if config_data['naabu_verbose_flag']:
        cmd.append("-v")
        
    try:
        await run_cmd(cmd, timeout=timeout)
        if (output_file.exists() and output_file.stat().st_size > 0) or \
           (output_file_json.exists() and output_file_json.stat().st_size > 0):
            logging.info(f"Port scanning completed, output: {output_file} / {output_file_json}")
            state_output = str(output_file_json) if output_file_json.exists() and output_file_json.stat().st_size > 0 else str(output_file)
            state[task_name] = {"completed": True, "output": state_output}
            return Path(state_output)
        logging.info("No open ports found or Naabu failed")
        state[task_name] = {"completed": True, "output": None}
        return None
    except asyncio.TimeoutError:
        logging.error(f"Naabu scan timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Naabu command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Naabu scan failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
