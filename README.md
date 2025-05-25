# Malphas

Malphas is a modular, automated reconnaissance and vulnerability scanning tool for security researchers and penetration testers. Built with Python 3.13, it performs DNS enumeration, subdomain discovery, live host probing, Shodan integration, vulnerability scanning, and more. Its asynchronous execution and flexible configuration make it efficient for professional security assessments.

## Key Features

- **DNS Enumeration**: Zone transfers and SRV record analysis with `dnsrecon`.
- **Subdomain Discovery**: Recursive enumeration using `subfinder` and optional `amass`.
- **Live Host Probing**: Concurrent host verification with `httpx`.
- **Shodan Integration**: Host exposure details via Shodan (requires API key).
- **Port Scanning**: Open port discovery with `naabu`.
- **Vulnerability Scanning**: Network and web scans with `nuclei` for low to critical issues.
- **URL Discovery**: Historical and active URL crawling with `waybackurls` and `gospider`.
- **CMS Detection**: Identifies WordPress, Joomla, and Drupal; includes `wpscan` for WordPress.
- **Login Portal Detection**: Detects login and admin pages.
- **SQL Injection Testing**: Tests login portals and query parameters with `sqlmap`.
- **OWASP ZAP Spidering**: Automated spidering via API-driven OWASP ZAP.
- **OpenVAS Scanning**: Comprehensive scans using local GVM via GMP API.
- **XSS Analysis**: XSS and DOM-based XSS detection with `dalfox`.
- **Open Redirect Testing**: Checks unvalidated redirects with `curl` and Python.
- **JavaScript Analysis**: JS endpoint discovery with `katana` and optional `ffuf` fuzzing.
- **Secrets Scanning**: GitHub repository secret scanning with `trufflehog`.

## Prerequisites

- **Python**: 3.8+ (tested up to 3.13).
- **Required Tools**: `subfinder`, `httpx`, `naabu`, `nuclei`, `waybackurls`, `dalfox`, `katana`, `trufflehog`, `ffuf`, `curl`, `zaproxy`, `sqlmap`, `dnsrecon`, `amass`, `gospider`, `wpscan`, `shodan`.
- **Python Dependencies** (in `requirements.txt`):
  - `python-gvm==24.3.0`
  - `shodan==1.31.0`
- **OWASP ZAP**: Installed and accessible.
- **OpenVAS/GVM**: Local installation with SSH and GMP enabled.
- **Sudo Access**: Passwordless `sudo` for `gvm-start` and `gvm-stop` (if using GVM).
- **API Keys**:
  - Shodan (required): [https://account.shodan.io](https://account.shodan.io).
  - WPScan (optional): [https://wpscan.com/api](https://wpscan.com/api).
- **Go**: For installing Go-based tools.
- **Git**: For cloning the repository.

## Installation

Malphas is distributed via a Git repository for easy setup and updates. Instructions are provided for common platforms.

### 1. Clone the Repository

```bash
git clone https://github.com/malphas/malphas.git
cd malphas
```

> **Note**: Replace `https://github.com/malphas/malphas.git` with the actual repository URL if different.

### 2. Install Dependencies

Run the `install_dependencies.sh` script to automate dependency installation, which detects your platform:

```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
```

Alternatively, install manually based on your platform:

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

> **Note**: Tools like `subfinder`, `httpx-toolkit`, `naabu`, `nuclei`, `dnsrecon`, `amass`, and `wpscan` may require source installation. Check their GitHub pages.

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

> **Note**: Install Homebrew if needed: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`.

#### Manual Installation (Any Platform)
- **Python Dependencies**: `pip install -r requirements.txt`
- **Go Tools**: Use `go install` for `waybackurls`, `dalfox`, `katana`, `trufflehog`, `ffuf`, `gospider`.
- **Other Tools**: Follow GitHub instructions for `subfinder`, `nuclei`, etc.
- **Shodan CLI**: `pip install shodan`.

### 3. Configure OpenVAS/GVM

- Set up GVM:
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

> **Note**: macOS GVM setup may require additional steps. See [GVM documentation](https://greenbone.github.io/docs/).

## Configuration

Create a `config.ini` file in the `malphas` directory. Use `which <tool>` to find tool paths on your system.

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

- **Tool Paths**: Adjust based on your system (e.g., `/usr/local/bin` for Go tools on macOS).
- **API Keys**:
  - `SHODAN_API_KEY`: Required for Shodan.
  - `WPSCAN_API_TOKEN`: Optional for WordPress scanning.
  - `ZAP_API_KEY`: For OWASP ZAP.
  - `OPENVAS_USERNAME`, `OPENVAS_PASSWORD`: For GVM.
- **Optional**:
  - `BXSS_URL`: Blind XSS testing.
  - `REDIRECT_URL`: Open redirect testing.

Find tool paths:
```bash
which subfinder
which zap.sh
which shodan
```

## Usage

Run a scan:
```bash
cd malphas
python -m malphas.main example.com --config config.ini --verbose
```

### Command-Line Options

- `--output, -o`: Output directory (default: `outputs`).
- `--config, -c`: Config file path (default: `config.ini`).
- `--skip-dns-enum`, `--skip-subdomain-enum`, `--skip-port-scan`, `--skip-vuln-scan`, `--skip-url-fetching`, `--skip-xss-analysis`, `--skip-js-discovery`, `--skip-secrets`, `--skip-open-redirects`, `--skip-advanced-xss`, `--skip-sqli`, `--skip-zap-scan`, `--skip-openvas-scan`, `--skip-cms-scan`: Skip specific phases.
- `--fuzz-with-ffuf`: Enable `ffuf` fuzzing.
- `--use-amass`: Include Amass for subdomains.
- `--verbose`: Detailed logging.

### Output Files

Results are in `outputs/example_com_<timestamp>/`:
- `dnsrecon.txt`, `subdomains_subfinder.txt`, `live_hosts_httpx.txt`, `shodan_results.json`, `ports_naabu.txt`, `vulnerabilities_network_nuclei.txt`, `cms_vulns.txt`, `wp_vulns_wpscan.txt`, `urls_combined.txt`, `login_portals.txt`, `sqlmap_vulns.txt`, `zap_spider.json`, `openvas_scan.json`, `xss_dalfox.txt`, `open_redirects.txt`, `js_endpoints_katana.txt`, `secrets_trufflehog_github_<domain>.json`, `summary_report_<timestamp>.json`.

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
    "file": "outputs/example_com_20250524_230200/shodan_results.json",
    "count": 3,
    "sample": ["ip_str: 93.94.226.100", "ip_str: 93.94.226.101"]
  },
  "cms": {
    "file": "outputs/example_com_20250524_230200/cms_vulns.txt",
    "count": 2,
    "sample": ["https://blog.example.com/wp-admin/"]
  },
  "openvas_scan": {
    "file": "outputs/example_com_20250524_230200/openvas_scan.json",
    "task_id": "123e4567-e89b-12d3-a456-426614174000"
  },
  "vulnerabilities_network": {
    "file": "outputs/example_com_20250524_230200/vulnerabilities_network_nuclei.txt",
    "count": 5,
    "sample": ["[high] CVE-2023-1234 detected"]
  }
}
```

## Troubleshooting

- **FileNotFoundError**:
  Check output directory permissions:
  ```bash
  chmod -R u+rw outputs
  ```

- **Scan Hangs**:
  Use verbose logging:
  ```bash
  python -m malphas.main example.com --verbose
  ```
  Skip slow phases:
  ```bash
  python -m malphas.main example.com --skip-subdomain-enum
  ```

- **Tool Not Found**:
  Verify paths:
  ```bash
  which curl
  which zap.sh
  which shodan
  ```

- **OWASP ZAP Errors**:
  Start ZAP manually:
  ```bash
  zap.sh -daemon -port 8081 -config view.disable=true -config api.key=your_zap_api_key_here
  ```

- **OpenVAS/GVM Errors**:
  Check setup:
  ```bash
  sudo gvm-check-setup
  sudo gvm-start
  ```

- **Shodan Errors**:
  Check API key:
  ```bash
  shodan init your_shodan_api_key_here
  shodan info
  ```

## License

GNU Affero General Public License v3.0. See `LICENSE` file.

## Disclaimer

Use Malphas only for authorized security testing. Obtain explicit permission from target system owners. Unauthorized use may violate laws.