# test/recon/sub_scans.py
import asyncio
import logging
from pathlib import Path
from typing import Optional
from ..utils import run_cmd

async def subfinder_enum(
    domain: str,
    output_dir: Path,
    subfinder_path: str,
    state: dict,
    rate_limit: int,
    timeout: int = 600
) -> Optional[Path]:
    """Enumerate subdomains using Subfinder."""
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
        "-silent", "-t", "50", "-rl", str(rate_limit)
    ]
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
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
    active: bool,
    rate_limit: int,
    timeout: int = 1800
) -> Optional[Path]:
    """Enumerate subdomains using Amass."""
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
        "-silent", "-timeout", "30"
    ]
    if active:
        cmd.append("-active")
    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists():
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
