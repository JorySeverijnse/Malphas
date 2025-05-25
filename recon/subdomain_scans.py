import asyncio
import logging
from pathlib import Path
from typing import Optional
from .utils import run_cmd

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