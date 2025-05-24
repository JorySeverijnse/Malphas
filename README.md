# Recon Ninja

Recon Ninja is an automated reconnaissance script for security researchers and penetration testers. It performs DNS enumeration, subdomain discovery, live host probing, Shodan scanning, vulnerability scanning, URL discovery, CMS checks (with WPScan for WordPress), login portal detection, SQL injection testing, XSS analysis, open redirect checks, JavaScript discovery, secrets scanning, and OWASP ZAP and OpenVAS scans. Modular, Python 3.8+, tested up to Python 3.13, with async execution.

## Features

- **DNS Enumeration**: `dnsrecon` for zone transfers, SRV records, etc.
- **Subdomain Enumeration**: `subfinder` and optional `amass` with recursive discovery.
- **Live Host Probing**: `httpx` with optimized concurrency.
- **Shodan Scanning**: Queries Shodan for host exposure (requires API key).
- **Port Scanning**: `naabu` with rate limiting.
- **Vulnerability Scanning**: `nuclei` for network and web vulnerabilities (low to critical).
- **URL Discovery**: `waybackurls` and `gospider` for historical and active crawling.
- **CMS Checks**: Detects WordPress, Joomla, Drupal; runs `wpscan` for WordPress.
- **Login Portal Detection**: Identifies login/admin pages for targeted scans.
- **SQL Injection**: `sqlmap` for login portals and query parameters.
- **OWASP ZAP Spider Scan**: Runs ZAP in background with API-driven spidering.
- **OpenVAS Scan**: Starts local GVM services and scans live hosts via GMP API.
- **XSS Analysis**: `dalfox` for XSS and DOM XSS with WAF bypass.
- **Open Redirects**: Checks unvalidated redirects with `curl` and Python.
- **SQLi Detection**: `nuclei` for SQLi in query parameters.
- **JavaScript Analysis**: `katana` for JS endpoints, optional `ffuf` fuzzing.
- **Secrets Scanning**: `trufflehog` for GitHub secrets.
- **Verbose Logging**: `--verbose` for debugging.
- **Skip Flags**: Skip specific phases (e.g., `--skip-openvas-scan`, `--skip-cms-scan`).

## Prerequisites

- **Python 3.8+**: Tested up to 3.13.
- **Tools**:
  - `subfinder`, `httpx`, `naabu`, `nuclei`, `waybackurls`, `dalfox`, `katana`, `trufflehog`, `ffuf`, `curl`, `zaproxy`, `sqlmap`, `dnsrecon`, `amass`, `gospider`, `wpscan`, `shodan`.
- **Python Dependencies**: `validators==0.22.0`, `python-gvm==24.7.0`, `shodan==1.31.0` (in `requirements.txt`).
- **OWASP ZAP**: Installed at `/usr/share/zaproxy/zap.sh`.
- **OpenVAS/GVM**: Installed locally with SSH and GMP enabled.
- **Sudo Access**: Passwordless `sudo` for `gvm-start` and `gvm-stop`.
- **Shodan API Key**: Required for Shodan scans (get from https://account.shodan.io).
- **WPScan API Token**: Optional for enhanced WordPress scanning (get from https://wpscan.com/api).

### Dependency Versions
| Tool          | Version       | Installation Method |
|---------------|---------------|---------------------|
| subfinder     | Latest        | `apt install subfinder` |
| httpx         | Latest        | `apt install httpx-toolkit` |
| naabu         | Latest        | `apt install naabu` |
| nuclei        | Latest        | `apt install nuclei` |
| waybackurls   | Latest        | `go install github.com/tomnomnom/waybackurls@latest` |
| dalfox        | v2            | `go install github.com/hahwul/dalfox/v2@latest` |
| katana        | Latest        | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| trufflehog    | Latest        | `go install github.com/trufflesecurity/trufflehog@latest` |
| ffuf          | v2            | `go install github.com/ffuf/ffuf/v2@latest` |
| sqlmap        | Latest        | `apt install sqlmap` |
| dnsrecon      | Latest        | `apt install dnsrecon` |
| amass         | Latest        | `apt install amass` |
| gospider      | Latest        | `go install github.com/jaeles-project/gospider@latest` |
| wpscan        | Latest        | `apt install wpscan` |
| shodan        | Latest        | `pip install shodan` |
| zaproxy       | Latest        | `apt install zaproxy` |
| openvas/gvm   | Latest        | `apt install openvas-scanner gvm` |

## Installation

1. **Create Directory**:
   ```bash
   mkdir vulnerability_finder
   cd vulnerability_finder
   ```

2. **Add Files**:
   - `main.py`, `config.py`, `utils.py`, `recon.py`, `summarize.py`, `requirements.txt`, `README.md`, `__init__.py`.
   - Create `__init__.py`:
     ```bash
     touch __init__.py
     ```

3. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Tools**:
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
   pip install shodan
   export PATH=$PATH:/home/someone/go/bin
   echo 'export PATH=$PATH:/home/someone/go/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

5. **Set Up OWASP ZAP**:
   - Verify installation:
     ```bash
     zap.sh -version
     ls /usr/share/zaproxy/zap.sh
     ```

6. **Set Up OpenVAS/GVM**:
   - Install and configure:
     ```bash
     sudo gvm-setup
     sudo gvm-check-setup
     ```
   - Create GMP user:
     ```bash
     sudo runuser -u _gvm -- gvmd --create-user=your-username --password=your-password
     ```
   - Enable SSH:
     ```bash
     sudo systemctl enable ssh
     sudo systemctl start ssh
     ```
   - Configure passwordless `sudo`:
     ```bash
     echo "your-username ALL=(ALL) NOPASSWD: /usr/sbin/gvm-start, /usr/sbin/gvm-stop" | sudo tee /etc/sudoers.d/gvm
     sudo chmod 0440 /etc/sudoers.d/gvm
     ```

7. **Set Up Shodan**:
   - Verify installation:
     ```bash
     shodan --version
     ```

8. **Set Up WPScan**:
   - Verify installation:
     ```bash
     wpscan --version
     ```

9. **Verify**:
   ```bash
   python -m vulnerability_finder.main --help
   python --version
   gvm-cli --version
   sqlmap --version
   dnsrecon --version
   amass --version
   gospider --version
   wpscan --version
   shodan --version
   ```

## Running the Script

```bash
cd /home/someone
python -m vulnerability_finder.main ah.nl --config vulnerability_finder/config.ini --verbose
```

## Configuration

Edit `config.ini`:
```ini
[Tools]
subfinder = /usr/bin/subfinder
httpx = /usr/bin/httpx
naabu = /usr/bin/naabu
nuclei = /usr/bin/nuclei
waybackurls = /home/someone/go/bin/waybackurls
dalfox = /home/someone/go/bin/dalfox
katana = /home/someone/go/bin/katana
trufflehog = /home/someone/go/bin/trufflehog
ffuf = /home/someone/go/bin/ffuf
curl = /usr/bin/curl
zap = /usr/share/zaproxy/zap.sh
sqlmap = /usr/bin/sqlmap
dnsrecon = /usr/bin/dnsrecon
amass = /usr/bin/amass
gospider = /home/someone/go/bin/gospider
wpscan = /usr/bin/wpscan
shodan = /home/someone/.local/bin/shodan

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

- Use `which <tool>` for paths (e.g., `which wpscan`, `which shodan`).
- Set `BXSS_URL` for blind XSS (optional).
- Set `REDIRECT_URL` for open redirect testing.
- Set `ZAP_API_URL` and `ZAP_API_KEY` for ZAP.
- Set `OPENVAS_USERNAME` and `OPENVAS_PASSWORD` for GVM.
- Set `WPSCAN_API_TOKEN` for enhanced WordPress scanning (optional).
- Set `SHODAN_API_KEY` for Shodan scans (required for Shodan).

## Usage

```bash
python -m vulnerability_finder.main ah.nl --verbose --use-amass
```

### Options

- `--output, -o`: Output directory (default: `outputs`).
- `--config, -c`: Config file (default: `config.ini`).
- `--skip-dns-enum`, `--skip-subdomain-enum`, `--skip-port-scan`, `--skip-vuln-scan`, `--skip-url-fetching`, `--skip-xss-analysis`, `--skip-js-discovery`, `--skip-secrets`, `--skip-open-redirects`, `--skip-advanced-xss`, `--skip-sqli`, `--skip-zap-scan`, `--skip-openvas-scan`, `--skip-cms-scan`: Skip phases.
- `--fuzz-with-ffuf`: Fuzz endpoints.
- `--use-amass`: Use Amass for subdomain enumeration.
- `--verbose`: Debug logging.

### Output

In `outputs/ah_nl_<timestamp>/`:
- `dnsrecon.txt`, `subdomains_subfinder.txt`, `subdomains_amass.txt`, `subdomains_combined.txt`, `live_hosts_httpx.txt`, `shodan_results.json`, `ports_naabu.txt`, `vulnerabilities_network_nuclei.txt`, `lfi_httpx.txt`, `cms_vulns.txt`, `wp_vulns_wpscan.txt`, `urls_wayback.txt`, `urls_gospider.txt`, `urls_combined.txt`, `login_portals.txt`, `sqlmap_vulns.txt`, `zap_spider.json`, `openvas_scan.json`, `xss_dalfox.txt`, `domxss_dalfox.txt`, `advanced_xss_dalfox.txt`, `open_redirects.txt`, `sqli_nuclei.txt`, `vulnerabilities_web_nuclei.txt`, `js_endpoints_katana.txt`, `fuzzed_endpoints_ffuf.json`, `secrets_trufflehog_github_<domain>.json`, `summary_report_<timestamp>.json`.

### Example Output (`summary_report_<timestamp>.json`)

```json
{
  "dns": {
    "file": "outputs/ah_nl_20250524_160000/dnsrecon.txt",
    "count": 10,
    "sample": ["A ah.nl 93.94.226.100", "MX ah.nl mail.ah.nl"]
  },
  "subdomains_subfinder": {
    "file": "outputs/ah_nl_20250524_160000/subdomains_subfinder.txt",
    "count": 50,
    "sample": ["www.ah.nl", "app.ah.nl"]
  },
  "shodan": {
    "file": "outputs/ah_nl_20250524_160000/shodan_results.json",
    "count": 3,
    "sample": ["ip_str: 93.94.226.100", "ip_str: 93.94.226.101"],
    "host_count": 3,
    "sample_hosts": ["93.94.226.100", "93.94.226.101"]
  },
  "cms": {
    "file": "outputs/ah_nl_20250524_160000/cms_vulns.txt",
    "count": 2,
    "sample": ["https://blog.ah.nl/wp-admin/", "https://blog.ah.nl/wp-content/"],
    "wordpress_vulns": {
      "plugins": 5,
      "themes": 2,
      "users": 3
    }
  },
  "openvas_scan": {
    "file": "outputs/ah_nl_20250524_160000/openvas_scan.json",
    "count": 1,
    "sample": [],
    "task_id": "123e4567-e89b-12d3-a456-426614174000",
    "host_count": 10
  },
  "vulnerabilities_network": {
    "file": "outputs/ah_nl_20250524_160000/vulnerabilities_network_nuclei.txt",
    "count": 5,
    "sample": ["[high] CVE-2023-1234 detected"],
    "severity_counts": {"low": 2, "medium": 1, "high": 2, "critical": 0}
  }
}
```

## Troubleshooting

- **FileNotFoundError**:
  ```bash
  chmod -R u+rw outputs
  ```
- **Hangs**:
  ```bash
  python -m vulnerability_finder.main ah.nl --verbose
  wc -l outputs/ah_nl_<timestamp>/subdomains_combined.txt
  ```
  Skip slow phases:
  ```bash
  python -m vulnerability_finder.main ah.nl --skip-subdomain-enum
  ```
- **Tool Not Found**:
  ```bash
  which curl
  which zap.sh
  which sqlmap
  which wpscan
  which shodan
  ```
- **ZAP API Errors**:
  - Verify path:
    ```bash
    ls /usr/share/zaproxy/zap.sh
    ```
  - Check API key in `config.ini`.
  - Manually start ZAP:
    ```bash
    /usr/share/zaproxy/zap.sh -daemon -port 8081 -config view.disable=true -config api.key=your_zap_api_key_here
    curl http://localhost:8081
    ```
  - Kill stuck processes:
    ```bash
    pkill -f zap.sh
    ```
- **OpenVAS Errors**:
  - Verify GVM:
    ```bash
    sudo gvm-check-setup
    systemctl status gvmd openvas-scanner ospd-openvas
    ```
  - Manually start GVM:
    ```bash
    sudo gvm-start
    ```
  - Verify SSH and credentials:
    ```bash
    ssh your_openvas_username@localhost
    ```
  - Check `config.ini`.
  - Access GVM web interface (`https://localhost:9392`).
  - Verify `sudo`:
    ```bash
    sudo -l -U your-username
    ```
- **SQLMap Errors**:
  - Verify installation:
    ```bash
    sqlmap --version
    ```
  - Check login portal output:
    ```bash
    cat outputs/ah_nl_<timestamp>/login_portals.txt
    ```
- **WPScan Errors**:
  - Verify installation:
    ```bash
    wpscan --version
    ```
  - Check WordPress detection:
    ```bash
    cat outputs/ah_nl_<timestamp>/cms_vulns.txt
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
- **Empty Outputs**: Normal for `ah.nl` or if scans fail (check `--verbose` logs).

## License

MIT License (request `LICENSE` file if needed).

## Disclaimer

For authorized use only. Obtain permission before scanning.