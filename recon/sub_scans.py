import asyncio
import logging
from pathlib import Path
from typing import Optional
from ..utils import run_cmd
from ..config import load_config # Added import

async def subfinder_enum(
    domain: str,
    output_dir: Path,
    subfinder_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Enumerate subdomains using Subfinder."""
    config_data = load_config(config_path) # Load config
    task_name = "subfinder_enum"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(subfinder_path).is_file():
        logging.error(f"Subfinder binary not found: {subfinder_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {subfinder_path}"}
        return None

    logging.info(f"Enumerating subdomains for: {domain}")
    output_file = output_dir / "subdomains_subfinder.txt"
    cmd = [
        subfinder_path, "-d", domain, "-o", str(output_file),
        "-silent", 
        "-t", str(config_data['subfinder_threads']), 
        "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists() and output_file.stat().st_size > 0: # Check size
            logging.info(f"Subdomain enumeration completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No subdomains found or subfinder failed")
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

async def amass_scan(
    domain: str,
    output_dir: Path,
    amass_path: str,
    state: dict,
    active: bool, # active is a direct param, good.
    rate_limit: int, # rate_limit is not directly used in amass enum cmd construction below
    timeout: int = 1800, # This is for run_cmd
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Enumerate subdomains using Amass."""
    config_data = load_config(config_path) # Load config
    task_name = "amass_enum"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(amass_path).is_file():
        logging.error(f"Amass binary not found: {amass_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {amass_path}"}
        return None

    logging.info(f"Enumerating subdomains with Amass for: {domain}")
    output_file = output_dir / "subdomains_amass.txt"
    cmd = [
        amass_path, "enum", "-d", domain, "-o", str(output_file),
        "-silent", 
        "-timeout", str(config_data['amass_flag_timeout']) # This is amass's own timeout for enum process
    ]
    # Amass rate limiting is usually via config file or more complex flags, 
    # `-max-dns-queries` is one if needed. The `rate_limit` param isn't directly mapped here.
    if active:
        cmd.append("-active")
    try:
        await run_cmd(cmd, timeout=timeout) # This is the overall timeout for run_cmd
        if output_file.exists() and output_file.stat().st_size > 0: # Check size
            logging.info(f"Amass enumeration completed, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No subdomains found or amass failed")
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
