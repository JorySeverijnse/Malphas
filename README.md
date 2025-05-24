# Malphas

Malphas is a modular, automated reconnaissance and vulnerability scanning tool designed for security researchers and penetration testers. Built with Python 3.8+ (tested up to Python 3.13), Malphas streamlines security assessments through DNS enumeration, subdomain discovery, live host probing, Shodan integration, vulnerability scanning, and more. Its asynchronous execution and flexible configuration ensure efficiency and adaptability for professional use.

## Key Features

- **DNS Enumeration**: Performs zone transfers and SRV record analysis with `dnsrecon`.
- **Subdomain Discovery**: Uses `subfinder` and optional `amass` for recursive subdomain enumeration.
- **Live Host Probing**: Verifies hosts concurrently with `httpx`.
- **Shodan Integration**: Queries host exposure details via Shodan (requires API key).
- **Port Scanning**: Discovers open ports with `naabu` and configurable rate limiting.
- **Vulnerability Scanning**: Scans for network and web vulnerabilities using `nuclei` (low to critical severity).
- **URL Discovery**: Crawls historical and active URLs with `waybackurls` and `gospider`.
- **CMS Detection**: Identifies WordPress, Joomla, and Drupal; includes `wpscan` for WordPress scans.
- **Login Portal Detection**: Detects login and admin pages for targeted testing.
- **SQL Injection Testing**: Tests login portals and query parameters with `sqlmap`.
- **OWASP ZAP Spidering**: Conducts automated spidering via API-driven OWASP ZAP.
- **OpenVAS Scanning**: Performs comprehensive scans using local GVM via GMP API.
- **XSS Analysis**: Detects XSS and DOM-based XSS with `dalfox`, including WAF bypass.
- **Open Redirect Testing**: Checks unvalidated redirects using `curl` and Python.
- **SQL Injection Detection**: Identifies SQLi vulnerabilities in query parameters with `nuclei`.
- **JavaScript Analysis**: Discovers JS endpoints with `katana` and optional `ffuf` fuzzing.
- **Secrets Scanning**: Scans GitHub repositories for exposed secrets using `trufflehog`.
- **Flexible Configuration**: Supports skip flags for scan phases and verbose logging.

## Prerequisites

- **Python Version**: Python 3.8 or higher (tested up to Python 3.13).
- **Required Tools**:
  - `subfinder`, `httpx`, `naabu`, `nuclei`, `waybackurls`, `dalfox`, `katana`, `trufflehog`, `ffuf`, `curl`, `zaproxy`, `sqlmap`, `dnsrecon`, `amass`, `gospider`, `wpscan`, `shodan`.
- **Python Dependencies** (listed in `requirements.txt`):
  - `python-gvm==24.3.0`
  - `shodan==1.31.0`
- **OWASP ZAP**: Installed and accessible (default: `/usr/share/zaproxy/zap.sh` on Linux).
- **OpenVAS/GVM**: Local installation with SSH and GMP enabled.
- **Sudo Access**: Passwordless `sudo` for `gvm-start` and `gvm-stop` (if using GVM).
- **API Keys**:
  - **Shodan API Key**: Required for Shodan scans ([https://account.shodan.io](https://account.shodan.io)).
  - **WPScan API Token**: Optional for enhanced WordPress scanning ([https://wpscan.com/api](https://wpscan.com/api)).
- **Go**: Required for installing Go-based tools (e.g., `waybackurls`, `dalfox`).
- **Git**: Required for cloning the repository.

## Installation

Malphas is distributed via a Git repository for ease of setup and updates. The following instructions are platform-agnostic, with specific commands for common operating systems (Debian/Ubuntu, Red Hat/Fedora, macOS, etc.).

### 1. Clone the Repository

Clone the Malphas repository to your local machine:
```bash
git clone https://github.com/malphas/malphas.git
cd malphas
```

> **Note**: Replace `https://github.com/malphas/malphas.git` with the actual repository URL if different.

### 2. Install Dependencies

Use the provided `install_dependencies.sh` script to automate dependency installation. The script detects your operating system and uses the appropriate package manager or source installation.

```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
```

Alternatively, manually install dependencies based on your platform:

#### Debian/Ubuntu
```bash
sudo apt update
sudo apt install -y python3 python3-pip curl git subfinder httpx-toolkit naabu nuclei zaproxy sqlmap dnsrecon amass wpscan openvas-scanner gvm
pip install -r requirements.txt
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/trufflesecurity/trufflehog@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/jaeles-project/gospider@latest
pip install shodan
sudo apt install -y seclists
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Red Hat/Fedora
```bash
sudo dnf install -y python3 python3-pip curl git openvas-scanner gvm
pip install -r requirements.txt
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/trufflesecurity/trufflehog@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/jaeles-project/gospider@latest
pip install shodan
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

> **Note**: Tools like `subfinder`, `httpx-toolkit`, `naabu`, `nuclei`, `dnsrecon`, `amass`, and `wpscan` may require manual installation from source or third-party repositories on Red Hat/Fedora. Check their respective GitHub pages for instructions.

#### macOS
```bash
brew install python3 curl git openvas gvm
pip install -r requirements.txt
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/trufflesecurity/trufflehog@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/jaeles-project/gospider@latest
pip install shodan
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

> **Note**: Install Homebrew if not already present (`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`). Tools like `subfinder`, `httpx-toolkit`, `naabu`, `nuclei`, `dnsrecon`, `amass`, and `wpscan` may require source installation.

#### Manual Installation (Any Platform)
If package managers are unavailable, install tools from source:
- **Python Dependencies**: `pip install -r requirements.txt`
- **Go Tools**: Use `go install` for `waybackurls`, `dalfox`, `katana`, `trufflehog`, `ffuf`, `gospider`.
- **Other Tools**: Follow instructions on their GitHub pages (e.g., [subfinder](https://github.com/projectdiscovery/subfinder), [nuclei](https://github.com/projectdiscovery/nuclei)).
- **Shodan CLI**: `pip install shodan`.

### 3. Configure OWASP ZAP

- Verify installation:
  ```bash
  zap.sh -version
  ```
- Default path: `/usr/share/zaproxy/zap.sh` (Linux) or `/Applications/OWASP\ ZAP.app/Contents/MacOS/zap.sh` (macOS).
- If installed elsewhere, note the path for `config.ini`.

### 4. Configure OpenVAS/GVM

- Install and set up GVM:
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
- Configure passwordless `sudo` for GVM (Linux):
  ```bash
  echo "your-username ALL=(ALL) NOPASSWD: /usr/sbin/gvm-start, /usr/sbin/gvm-stop" | sudo tee /etc/sudoers.d/gvm
  sudo chmod 0440 /etc/sudoers.d/gvm
  ```

> **Note**: On macOS, GVM setup may require additional configuration. Refer to [GVM documentation](https://greenbone.github.io/docs/).

### 5. Configure Shodan

- Verify installation:
  ```bash
  shodan --version
  ```

### 6. Configure WPScan

- Verify installation:
  ```bash
  wpscan --version
  ```

### 7. Verify Installation

Check that all components are installed:
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

Create a `config.ini` file in the `malphas` directory to specify tool paths and API keys. Use `which <tool>` to find paths on your system.

```ini
[Tools]
subfinder = /usr/bin/subfinder
httpx = /usr/bin/httpx
naabu = /usr/bin/naabu
nuclei = /usr/bin/nuclei
waybackurls = /usr/local/bin/waybackurls
dalfox = /usr/local/bin/dalfox
katana = /usr/local/bin/katana
trufflehog = /usr/local/bin/trufflehog
ffuf = /usr/local/bin/ffuf
curl = /usr/bin/curl
zap = /usr/share/zaproxy/zap.sh
sqlmap = /usr/bin/sqlmap
dnsrecon = /usr/bin/dnsrecon
amass = /usr/bin/amass
gospider = /usr/local/bin/gospider
wpscan = /usr/bin/wpscan
shodan = /usr/local/bin/shodan

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

- **Tool Paths**: Update paths based on your system (e.g., `/usr/local/bin` for Go tools on macOS, `$HOME/go/bin` for Linux if installed via Go).
- **API Keys**:
  - Set `SHODAN_API_KEY` for Shodan scans (required).
  - Set `WPSCAN_API_TOKEN` for enhanced WordPress scanning (optional).
  - Configure `ZAP_API_KEY` for OWASP ZAP.
  - Specify `OPENVAS_USERNAME` and `OPENVAS_PASSWORD` for GVM.
- **Optional Settings**:
  - `BXSS_URL`: For blind XSS testing.
  - `REDIRECT_URL`: For open redirect testing.

To find tool paths:
```bash
which subfinder
which zap.sh
which shodan
```

## Usage

Run a scan from the project directory:
```bash
cd malphas
python -m malphas.main example.com --config config.ini --verbose
```

### Command-Line Options

- `--output, -o`: Output directory (default: `outputs`).
- `--config, -c`: Configuration file path (default: `config.ini`).
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
    "file": "outputs/example_com_20250524_230200/dnsrecon.txt",
    "count": 10,
    "sample": ["A example.com 93.94.226.100", "MX example.com mail.example.com"]
  },
  "subdomains_subfinder": {
    "file": "outputs/example_com_20250524_230200/subdomains_subfinder.txt",
    "count": 50,
    "sample": ["www.example.com", "app.example.com"]
  },
  "shodan": {
    "file": "output/example_com_20250524_230200/shodan_results.json",
    "count": 3,
    "sample": ["ip_str: 93.94.226.100", "ip_str: 93.94.226.101"],
    "host_count": 3,
    "sample_hosts": ["93.94.226.100", "93.94.226.101"]
  },
  "cms": {
    "file": "outputs/example_com_20250524_230200/cms_vulns.txt",
    "count": 2,
    "sample": ["https://blog.example.com/wp-admin/", "https://blog.example.com/wp-content/"],
    "wordpress_vulns": {
      "plugins": 5,
      "themes": 2,
      "users": 3
    }
  },
  "openvas_scan": {
    "file": "outputs/example_com_20250524_230200/openvas_scan.json",
    "count": 1,
    "sample": [],
    "task_id": "123e4567-e89b-12d3-a456-426614174000",
    "host_count": 10
  },
  "vulnerabilities_network": {
    "file": "outputs/example_com_20250524_230200/vulnerabilities_network_nuclei.txt",
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
  Enable verbose logging:
  ```bash
  python -m malphas.main example.com --verbose
  wc -l outputs/example_com_<timestamp>/subdomains_combined.txt
  ```
  Skip slow phases:
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
  - Verify installation:
    ```bash
    zap.sh -version
    ```
  - Ensure `ZAP_API_KEY` is set in `config.ini`.
  - Start ZAP manually:
    ```bash
    zap.sh -daemon -port 8081 -config view.disable=true -config api.key=your_zap_api_key_here
    curl http://localhost:8081
    ```
  - Terminate stuck processes:
    ```bash
    pkill -f zap.sh
    ```

- **OpenVAS/GVM Errors**:
  - Verify setup:
    ```bash
    sudo gvm-check-setup
    ```
  - Check services (Linux):
    ```bash
    systemctl status gvmd openvas-scanner ospd-openvas
    ```
  - Start GVM:
    ```bash
    sudo gvm-start
    ```
  - Verify SSH and credentials:
    ```bash
    ssh your_openvas_username@localhost
    ```
  - Ensure `OPENVAS_USERNAME` and `OPENVAS_PASSWORD` are set in `config.ini`.
  - Access GVM web interface: `https://localhost:9392`.
  - Confirm `sudo` permissions (Linux):
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
  Empty results may occur for certain domains or failed scans. Use `--verbose` to inspect logs.

## License

Malphas is licensed under the GNU Affero General Public License v3.0. See the `LICENSE` file for details.

## Disclaimer

Malphas is intended for authorized security testing only. Always obtain explicit permission from the target system's owner before scanning. Unauthorized use may violate applicable laws and regulations.