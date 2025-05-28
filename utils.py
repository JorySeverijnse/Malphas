import asyncio
import logging
from pathlib import Path
from typing import List, Optional

async def run_cmd(cmd: List[str], output_file: Optional[Path] = None, timeout: int = 3600) -> Optional[str]:
    """Run a command asynchronously and optionally save output to a file."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        output = stdout.decode().strip()
        if stderr:
            logging.debug(f"Command {cmd[0]} stderr: {stderr.decode().strip()}")
        if process.returncode != 0:
            logging.error(f"Command {cmd[0]} failed with code {process.returncode}")
            return None
        if output_file:
            with output_file.open('w') as f:
                f.write(output + '\n')
        return output
    except asyncio.TimeoutError:
        logging.error(f"Command {cmd[0]} timed out after {timeout} seconds")
        return None
    except Exception as e:
        logging.error(f"Command {cmd[0]} failed: {e}")
        return None

def read_file_lines_or_empty(file_path: Path) -> List[str]:
    """Read lines from a file, returning an empty list if the file doesn't exist or fails."""
    try:
        if file_path.exists():
            with file_path.open() as f:
                return [line.strip() for line in f if line.strip()]
        return []
    except Exception as e:
        logging.error(f"Failed to read file {file_path}: {e}")
        return []
