import asyncio
import logging
import json
from pathlib import Path
from typing import Optional
from ..utils import run_cmd
from ..config import load_config # Added import

async def dnsrecon_scan(
    domain: str,
    output_dir: Path,
    dnsrecon_path: str,
    state: dict,
    rate_limit: int, # Not directly used in dnsrecon command structure from config, but kept for signature consistency
    timeout: int = 600,
    wordlist_for_subdomains: Optional[Path] = None,
    config_path: str = "config.ini" # Added config_path
) -> Optional[Path]:
    """Perform DNS reconnaissance using dnsrecon."""
    config_data = load_config(config_path) # Load config
    task_name = "dnsrecon_scan"
    if state.get(task_name, {}).get("completed"):
        logging.info(f"Skipping {task_name}, already completed: {state[task_name]['output']}")
        return Path(state[task_name]["output"]) if state[task_name].get("output") else None

    if not Path(dnsrecon_path).is_file():
        logging.error(f"Dnsrecon binary not found: {dnsrecon_path}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {dnsrecon_path}"}
        return None
    if wordlist_for_subdomains and not wordlist_for_subdomains.is_file(): # wordlist_for_subdomains is a func param
        logging.error(f"Wordlist for subdomains not found: {wordlist_for_subdomains}")
        state[task_name] = {"completed": False, "output": None, "error": f"File not found: {wordlist_for_subdomains}"}
        return None

    logging.info(f"Running DNS reconnaissance for: {domain}")
    output_file = output_dir / "dnsrecon.json"
    cmd = [
        dnsrecon_path, "-d", domain, 
        "-t", config_data['dnsrecon_scan_types'], 
        "--json", str(output_file),
        "--threads", str(config_data['dnsrecon_threads'])
    ]
    if wordlist_for_subdomains:
        cmd.extend(["-w", str(wordlist_for_subdomains)]) 

    try:
        await run_cmd(cmd, timeout=timeout)
        if output_file.exists() and output_file.stat().st_size > 0: # Check size for json
            logging.info(f"DNS reconnaissance completed successfully, output: {output_file}")
            state[task_name] = {"completed": True, "output": str(output_file)}
            return output_file
        logging.info("No DNS records found or dnsrecon failed")
        state[task_name] = {"completed": True, "output": None} # success if no records
        return None
    except asyncio.TimeoutError:
        logging.error(f"Dnsrecon timed out after {timeout} seconds")
        state[task_name] = {"completed": False, "output": None, "error": f"Timeout after {timeout}s"}
        return None
    except FileNotFoundError as e:
        logging.error(f"Dnsrecon command not found: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
    except Exception as e:
        logging.error(f"Dnsrecon failed: {e}")
        state[task_name] = {"completed": False, "output": None, "error": str(e)}
        return None
