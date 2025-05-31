import asyncio
import logging
from pathlib import Path
from typing import List, Optional

# Define a custom exception for command execution errors
class CommandExecutionError(RuntimeError):
    def __init__(self, message, stderr=None, returncode=None):
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode

async def run_cmd(cmd: List[str], output_file: Optional[Path] = None, timeout: int = 3600) -> str:
    """
    Run a command asynchronously, return its stdout, and optionally save output to a file.
    Raises CommandExecutionError for command failures, asyncio.TimeoutError for timeouts,
    and FileNotFoundError if the command is not found.
    """
    cmd_str = ' '.join(cmd) # For logging
    logging.debug(f"Executing command: {cmd_str} with timeout {timeout}s")
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            logging.error(f"Command '{cmd_str}' timed out after {timeout} seconds. Killing process.")
            try:
                process.kill()
                await process.wait() # Ensure the process is terminated
            except ProcessLookupError:
                logging.debug(f"Process for '{cmd_str}' already terminated.")
            except Exception as e: # pylint: disable=broad-except
                logging.warning(f"Error during process kill for '{cmd_str}': {e}")
            raise # Re-raise asyncio.TimeoutError to be caught by the caller

        stdout_output = stdout_bytes.decode(errors='ignore').strip()
        stderr_output = stderr_bytes.decode(errors='ignore').strip()

        if stderr_output:
            # Log stderr as debug unless it's a critical error indicator along with non-zero return code
            if process.returncode != 0:
                 logging.error(f"Command '{cmd_str}' stderr: {stderr_output}")
            else:
                 logging.debug(f"Command '{cmd_str}' stderr: {stderr_output}")

        if process.returncode != 0:
            error_message = f"Command '{cmd_str}' failed with code {process.returncode}."
            logging.error(error_message)
            # Include stderr in the exception if available
            raise CommandExecutionError(error_message, stderr=stderr_output, returncode=process.returncode)
        
        if output_file:
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True) # Ensure output directory exists
                with output_file.open('w', encoding='utf-8') as f:
                    f.write(stdout_output + '\n')
                logging.debug(f"Command '{cmd_str}' output saved to {output_file}")
            except IOError as e:
                logging.error(f"Failed to write command output to {output_file} for '{cmd_str}': {e}")
                # Decide if this should also raise an exception or just log
        
        return stdout_output

    except FileNotFoundError as e:
        # This occurs if the executable in cmd[0] is not found
        logging.error(f"Command not found: {cmd[0]}. Full command: '{cmd_str}'. Error: {e}")
        raise # Re-raise FileNotFoundError to be caught by the caller

    except asyncio.TimeoutError: # Should be caught by the inner try-except now, but as a safeguard
        logging.error(f"Outer timeout catcher for '{cmd_str}' (this shouldn't be common).")
        raise

    except CommandExecutionError: # Re-raise if it was raised internally
        raise

    except Exception as e:
        # Catch any other unexpected errors during process creation or initial communication
        logging.error(f"Command '{cmd_str}' failed with an unexpected error: {e}", exc_info=True)
        raise CommandExecutionError(f"Unexpected error executing command '{cmd_str}': {e}", stderr=str(e))


def read_file_lines_or_empty(file_path: Path) -> List[str]:
    """Read lines from a file, returning an empty list if the file doesn't exist or fails."""
    try:
        if file_path.exists() and file_path.is_file():
            with file_path.open('r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            logging.debug(f"File not found or is not a file, returning empty list: {file_path}")
            return []
    except Exception as e:
        logging.error(f"Failed to read file {file_path}: {e}")
        return []
