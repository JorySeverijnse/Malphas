# Malphas

Malphas is a professional, modular, and automated reconnaissance and vulnerability scanning tool designed for security researchers and penetration testers. Built with Python 3.8+ (tested up to Python 3.13), Malphas performs comprehensive security assessments, including DNS enumeration, subdomain discovery, live host probing, Shodan integration, vulnerability scanning, and more. Its asynchronous execution and flexible configuration make it ideal for efficient and targeted security testing.

## Key Features

- **DNS Enumeration**: Uses `dnsrecon` for zone transfers, SRV records, and other DNS data.
- **Subdomain Discovery**: Employs `subfinder` and optional `amass` for recursive subdomain enumeration.
- **Live Host Probing**: Utilizes `httpx` for concurrent host verification.
- **Shodan Integration**: Queries Shodan for host exposure details (requires API key).
- **Port Scanning**: Performs port discovery with `naabu` and configurable rate limiting.
- **Vulnerability Scanning**: Conducts network and web scans with `nuclei` for low to critical vulnerabilities.
- **URL Discovery**: Combines `waybackurls` and `gospider` for historical and active URL crawling.
- **CMS Detection**: Identifies WordPress, Joomla, and Drupal; includes `wpscan` for WordPress-specific scans.
- **Login Portal Detection**: Detects login and admin pages for targeted assessments.
- **SQL Injection Testing**: Tests login portals and query parameters with `sqlmap`.
- **OWASP ZAP Spidering**: Performs automated spidering via API-driven OWASP ZAP scans.
- **OpenVAS Scanning**: Executes comprehensive scans using local GVM services via GMP API.
- **XSS Analysis**: Detects XSS and DOM-based XSS with `dalfox`, including WAF bypass techniques.
- **Open Redirect Testing**: Checks unvalidated redirects using `curl` and Python-based analysis.
- **SQL Injection Detection**: Identifies SQLi vulnerabilities in query parameters with `nuclei`.
- **JavaScript Analysis**: Discovers JS endpoints with `katana` and optional `ffuf` fuzzing.
- **Secrets Scanning**: Scans GitHub repositories for exposed secrets using `trufflehog`.
- **Flexible Configuration**: Supports skip flags for specific scan phases and verbose logging.

## Prerequisites

- **Python Version**: Python 3.8 or higher (tested up to Python 3.13).
- **Required Tools**:
  - `subfinder`, `httpx`, `naabu`, `nuclei`, `waybackurls`, `dalfox`, `katana`, `trufflehog`, `ffuf`, `curl`, `zaproxy`, `sqlmap`, `dnsrecon`, `amass`, `gospider`, `wpscan`, `shodan`.
- **Python Dependencies** (listed in `requirements.txt`):
  - `python-gvm==24.3.0`
  - `shodan==1.31.0`
- **OWASP ZAP**: Must be installed at `/usr/share/zaproxy/zap.sh`.
- **OpenVAS/GVM**: Requires local installation with SSH and GMP enabled.
- **Sudo Access**: Passwordless `sudo` required for `gvm-start` and `gvm-stop`.
- **API Keys**:
  - **Shodan API Key**: Required for Shodan scans (obtain from [https://account.shodan.io](https://account.shodan.io)).
  - **WPScan API Token**: Optional for enhanced WordPress scanning (obtain from [https://wpscan.com/api](https://wpscan.com/api)).

### Tool Versions

| Tool          | Version | Installation Command                            |
|---------------|---------|-----------------------------------------------|
| subfinder     | Latest  | `apt install subfinder`                       |
| httpx         | Latest  | `apt install httpx-toolkit`                   |
| naabu         | Latest  | `apt install naabu`                           |
| nuclei        | Latest  | `apt install nuclei`                          |
| waybackurls   | Latest  | `go install github.com/tomnomnom/waybackurls@latest` |
| dalfox        | v2      | `go install github.com/hahwul/dalfox/v2@latest` |
| katana        | Latest  | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| trufflehog    | Latest  | `go install github.com/trufflesecurity/trufflehog@latest` |
| ffuf          | v2      | `go install github.com/ffuf/ffuf/v2@latest`   |
| sqlmap        | Latest  | `apt install sqlmap`                          |
| dnsrecon      | Latest  | `apt install dnsrecon`                        |
| amass         | Latest  | `apt install amass`                           |
| gospider      | Latest  | `go install github.com/jaeles-project/gospider@latest` |
| wpscan        | Latest  | `apt install wpscan`                          |
| shodan        | Latest  | `pip install shodan`                          |
| zaproxy       | Latest  | `apt install zaproxy`                         |
| openvas/gvm   | Latest  | `apt install openvas-scanner gvm`             |

## Installation

1. **Create Project Directory**:
   ```bash
   mkdir malphas
   cd malphas
   ```

2. **Add Project Files**:
   - Include `main.py`, `config.py`, `utils.py`, `recon.py`, `summarize.py`, `requirements.txt`, `install_dependencies.sh`, `README.md`, and `__init__.py`.
   - Create an empty `__init__.py`:
     ```bash
     touch __init__.py
     ```

3. **Install Dependencies**:
   - Run the provided `install_dependencies.sh` script to automate tool and dependency installation:
     ```bash
     chmod +x install_dependencies.sh
     ./install_dependencies.sh
     ```
   - Alternatively, manually install dependencies:
     ```bash
     sudo apt update
     sudo apt install -y subfinder httpx-toolkit naabu nuclei curl zaproxy openvas-scanner gvm sqlmap dnsrecon amass wpscan
     go install github.com/tomnomnom/waybackurls@latest
     go install github.com/hahwul/dalfox/v2@latest
     go install github.com/projectdiscovery/katana/cmd/katana@latest
     go install github.com/trufflesecurity/trufflehog@latest
     go install github.com/ffuf/ffuf/v2@latest
     go install github.com/jaeles-project/gospider@latest
     sudo apt install -y seclists
     pip install -r requirements.txt
     export PATH=$PATH:$HOME/go/bin
     echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
     source ~/.bashrc
     ```

4. **Configure OWASP ZAP**:
   - Verify installation:
     ```bash
     zap.sh -version
     ls /usr/share/zaproxy/zap.sh
     ```

5. **Configure OpenVAS/GVM**:
   - Install and configure GVM:
     ```bash
     sudo gvm-setup
     sudo gvm-check-setup
     ```
   - Create a GMP user:
     ```bash
     sudo runuser -u _gvm -- gvmd --create-user=your-username --password=your-password
     ```
   - Enable SSH:
     ```bash
     sudo systemctl enable ssh
     sudo systemctl start ssh
     ```
   - Configure passwordless `sudo` for GVM:
     ```bash
     echo "your-username ALL=(ALL) NOPASSWD: /usr/sbin/gvm-start, /usr/sbin/gvm-stop" | sudo tee /etc/sudoers.d/gvm
     sudo chmod 0440 /etc/sudoers.d/gvm
     ```

6. **Configure Shodan**:
   - Verify installation:
     ```bash
     shodan --version
     ```

7. **Configure WPScan**:
   - Verify installation:
     ```bash
     wpscan --version
     ```

8. **Verify Installation**:
   ```bash
   python -m malphas.main --help
   python --version
   gvm-cli --version
   sqlmap --version
   dnsrecon --version
   amass --version
   gospider --version
   wpscan --version
   shodan --version
   ```

## Configuration

Create and edit a `config.ini` file in the project directory to specify tool paths and API keys:
```ini
[Tools]
subfinder = /usr/bin/subfinder
httpx = /usr/bin/httpx
naabu = /usr/bin/naabu
nuclei = /usr/bin/nuclei
waybackurls = /home/your-username/go/bin/waybackurls
dalfox = /home/your-username/go/bin/dalfox
katana = /home/your-username/go/bin/katana
trufflehog = /home/your-username/go/bin/trufflehog
ffuf = /home/your-username/go/bin/ffuf
curl = /usr/bin/curl
zap = /usr/share/zaproxy/zap.sh
sqlmap = /usr/bin/sqlmap
dnsrecon = /usr/bin/dnsrecon
amass = /usr/bin/amass
gospider = /home/your-username/go/bin/gospider
wpscan = /usr/bin/wpscan
shodan = /home/your-username/.local/bin/shodan

[Settings]
BXSS_URL =
REDIRECT_URL = http://localhost:8000
ZAP_API_URL = http://localhost:8081
ZAP_API_KEY = your_zap_api_key_here
OPENVAS_USERNAME = your_openvas_username
OPENVAS_PASSWORD = your_openvas_password
WPSCAN_API_TOKEN = your_wpscan_api_token_here
SHODAN_API_KEY = your_shodan_api_key_here
```

- Use `which <tool>` to verify tool paths (e.g., `which wpscan`, `which shodan`).
- Replace `your-username` with your actual user directory path.
- Set `BXSS_URL` for blind XSS testing (optional).
- Configure `REDIRECT_URL` for open redirect testing.
- Provide `ZAP_API_URL` and `ZAP_API_KEY` for OWASP ZAP integration.
- Specify `OPENVAS_USERNAME` and `OPENVAS_PASSWORD` for GVM scans.
- Include `WPSCAN_API_TOKEN` for enhanced WordPress scanning (optional).
- Set `SHODAN_API_KEY` for Shodan integration (required for Shodan scans).

## Usage

Run a scan from the project directory:
```bash
cd /home/your-username/malphas
python -m malphas.main example.com --config config.ini --verbose
```

### Command-Line Options

- `--output, -o`: Specify output directory (default: `outputs`).
- `--config, -c`: Path to configuration file (default: `config.ini`).
- `--skip-dns-enum`, `--skip-subdomain-enum`, `--skip-port-scan`, `--skip-vuln-scan`, `--skip-url-fetching`, `--skip-xss-analysis`, `--skip-js-discovery`, `--skip-secrets`, `--skip-open-redirects`, `--skip-advanced-xss`, `--skip-sqli`, `--skip-zap-scan`, `--skip-openvas-scan`, `--skip-cms-scan`: Skip specific scan phases.
- `--fuzz-with-ffuf`: Enable endpoint fuzzing with `ffuf`.
- `--use-amass`: Include Amass for subdomain enumeration.
- `--verbose`: Enable detailed debug logging.

### Output Files

Results are stored in `outputs/example_com_<timestamp>/` with files such as:
- `dnsrecon.txt`, `subdomains_subfinder.txt`, `subdomains_amass.txt`, `live_hosts_httpx.txt`, `shodan_results.json`, `ports_naabu.txt`, `vulnerabilities_network_nuclei.txt`, `lfi_httpx.txt`, `cms_vulns.txt`, `wp_vulns_wpscan.txt`, `urls_wayback.txt`, `urls_gospider.txt`, `urls_combined.txt`, `login_portals.txt`, `sqlmap_vulns.txt`, `zap_spider.json`, `openvas_scan.json`, `xss_dalfox.txt`, `domxss_dalfox.txt`, `advanced_xss_dalfox.txt`, `open_redirects.txt`, `sqli_nuclei.txt`, `vulnerabilities_web_nuclei.txt`, `js_endpoints_katana.txt`, `fuzzed_endpoints_ffuf.json`, `secrets_trufflehog_github_<domain>.json`, `summary_report_<timestamp>.json`.

### Example Summary Report (`summary_report_<timestamp>.json`)

```json
{
  "dns": {
    "file": "outputs/example_com_20250524_223100/dnsrecon.txt",
    "count": 10,
    "sample": ["A example.com 93.94.226.100", "MX example.com mail.example.com"]
  },
  "subdomains_subfinder": {
    "file": "outputs/example_com_20250524_223100/subdomains_subfinder.txt",
    "count": 50,
    "sample": ["www.example.com", "app.example.com"]
  },
  "shodan": {
    "file": "outputs/example_com_20250524_223100/shodan_results.json",
    "count": 3,
    "sample": ["ip_str: 93.94.226.100", "ip_str: 93.94.226.101"],
    "host_count": 3,
    "sample_hosts": ["93.94.226.100", "93.94.226.101"]
  },
  "cms": {
    "file": "outputs/example_com_20250524_223100/cms_vulns.txt",
    "count": 2,
    "sample": ["https://blog.example.com/wp-admin/", "https://blog.example.com/wp-content/"],
    "wordpress_vulns": {
      "plugins": 5,
      "themes": 2,
      "users": 3
    }
  },
  "openvas_scan": {
    "file": "outputs/example_com_20250524_223100/openvas_scan.json",
    "count": 1,
    "sample": [],
    "task_id": "123e4567-e89b-12d3-a456-426614174000",
    "host_count": 10
  },
  "vulnerabilities_network": {
    "file": "outputs/example_com_20250524_223100/vulnerabilities_network_nuclei.txt",
    "count": 5,
    "sample": ["[high] CVE-2023-1234 detected"],
    "severity_counts": {"low": 2, "medium": 1, "high": 2, "critical": 0}
  }
}
```

## Troubleshooting

- **FileNotFoundError**:
  Ensure output directory permissions:
  ```bash
  chmod -R u+rw outputs
  ```

- **Scan Hangs**:
  Enable verbose logging to diagnose:
  ```bash
  python -m malphas.main example.com --verbose
  wc -l outputs/example_com_<timestamp>/subdomains_combined.txt
  ```
  Skip slow phases if needed:
  ```bash
  python -m malphas.main example.com --skip-subdomain-enum
  ```

- **Tool Not Found**:
  Verify tool paths:
  ```bash
  which curl
  which zap.sh
  which sqlmap
  which wpscan
  which shodan
  ```

- **OWASP ZAP API Errors**:
  - Verify ZAP installation:
    ```bash
    ls /usr/share/zaproxy/zap.sh
    ```
  - Ensure `ZAP_API_KEY` is set in `config.ini`.
  - Start ZAP manually:
    ```bash
    /usr/share/zaproxy/zap.sh -daemon -port 8081 -config view.disable=true -config api.key=your_zap_api_key_here
    curl http://localhost:8081
    ```
  - Terminate stuck processes:
    ```bash
    pkill -f zap.sh
    ```

- **OpenVAS/GVM Errors**:
  - Verify GVM setup:
    ```bash
    sudo gvm-check-setup
    systemctl status gvmd openvas-scanner ospd-openvas
    ```
  - Start GVM manually:
    ```bash
    sudo gvm-start
    ```
  - Verify SSH and credentials:
    ```bash
    ssh your_openvas_username@localhost
    ```
  - Ensure `OPENVAS_USERNAME` and `OPENVAS_PASSWORD` are set in `config.ini`.
  - Access the GVM web interface at `https://localhost:9392`.
  - Confirm `sudo` permissions:
    ```bash
    sudo -l -U your-username
    ```

- **SQLMap Errors**:
  - Verify installation:
    ```bash
    sqlmap --version
    ```
  - Check login portal detection:
    ```bash
    cat outputs/example_com_<timestamp>/login_portals.txt
    ```

- **WPScan Errors**:
  - Verify installation:
    ```bash
    wpscan --version
    ```
  - Check CMS detection:
    ```bash
    cat outputs/example_com_<timestamp>/cms_vulns.txt
    ```
  - Set `WPSCAN_API_TOKEN` in `config.ini` for enhanced scanning.

- **Shodan Errors**:
  - Verify installation:
    ```bash
    shodan --version
    ```
  - Check API key and credits:
    ```bash
    shodan init your_shodan_api_key_here
    shodan info
    ```
  - Ensure `SHODAN_API_KEY` is set in `config.ini`.

- **Empty Outputs**:
  Empty results may occur for certain domains or if scans fail. Use `--verbose` to inspect logs.

## License

Malphas is licensed under the GNU Affero General Public License v3.0. See the `LICENSE` file for details.

## Disclaimer

Malphas is designed for authorized security testing only. Always obtain explicit permission from the target system's owner before conducting scans. Unauthorized use may violate applicable laws and regulations.