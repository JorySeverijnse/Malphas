# tower/config.py
import configparser
from pathlib import Path

def load_config(config_path: str) -> dict:
    """Load configuration from a config file."""
    config = configparser.ConfigParser()
    config.read(config_path)
    
    settings = {
        "dnsrecon_path": config.get("Settings", "DNSRECON_PATH", fallback="/usr/bin/dnsrecon"),
        "subfinder_path": config.get("Settings", "SUBFINDER_PATH", fallback="/usr/bin/subfinder"),
        "amass_path": config.get("Settings", "AMASS_PATH", fallback="/usr/bin/amass"),
        "httpx_path": config.get("Settings", "HTTPX_PATH", fallback="/usr/bin/httpx"),
        "shodan_path": config.get("Settings", "SHODAN_PATH", fallback="/usr/bin/shodan"),
        "shodan_api_key": config.get("Settings", "SHODAN_API_KEY", fallback=""),
        "naabu_path": config.get("Settings", "NAABU_PATH", fallback="/usr/bin/naabu"),
        "nuclei_path": config.get("Settings", "NUCLEI_PATH", fallback="/usr/bin/nuclei"),
        "wpscan_path": config.get("Settings", "WPSCAN_PATH", fallback="/usr/bin/wpscan"),
        "wpscan_api_token": config.get("Settings", "WPSCAN_API_TOKEN", fallback=""),
        "waybackurls_path": config.get("Settings", "WAYBACKURLS_PATH", fallback="/usr/bin/waybackurls"),
        "gospider_path": config.get("Settings", "GOSPIDER_PATH", fallback="/usr/bin/gospider"),
        "sqlmap_path": config.get("Settings", "SQLMAP_PATH", fallback="/usr/bin/sqlmap"),
        "curl_path": config.get("Settings", "CURL_PATH", fallback="/usr/bin/curl"),
        "zap_api_url": config.get("Settings", "ZAP_API_URL", fallback="http://localhost:8080"),
        "zap_api_key": config.get("Settings", "ZAP_API_KEY", fallback=""),
        "openvas_username": config.get("Settings", "OPENVAS_USERNAME", fallback=""),
        "openvas_password": config.get("Settings", "OPENVAS_PASSWORD", fallback=""),
        "dalfox_path": config.get("Settings", "DALFOX_PATH", fallback="/usr/bin/dalfox"),
        "bxss_url": config.get("Settings", "BXSS_URL", fallback=""),
        "redirect_url": config.get("Settings", "REDIRECT_URL", fallback="https://example.com"),
        "katana_path": config.get("Settings", "KATANA_PATH", fallback="/path/to/katana"),
        "ffuf_path": config.get("Settings", "FFUF_PATH", fallback="/path/to/ffuf"),
        "trufflehog_path": config.get("Settings", "TRUFFLEHOG_PATH", fallback="/path/to/trufflehog"),
        "wordlist": config.get("Settings", "WORDLIST", fallback="/path/to/wordlists/seclists/Discovery/Web-Content/Common.txt"),
        "sqlmap_level": config.getint("ToolSettings", "sqlmap_level", fallback=2),
        "sqlmap_risk": config.getint("ToolSettings", "sqlmap_risk", fallback=2),
        "dns_wordlist": config.get("Dictionaries", "DNS_WORDLIST", fallback="/path/to/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        "lfi_payloads": config.get("Dictionaries", "LFI_PAYLOADS", fallback="").split(",") if config.get("Dictionaries", "LFI_PAYLOADS", fallback="") else ["../../../../etc/passwd", "../../windows/win.ini"],
        "cms_paths": config.get("Dictionaries", "CMS_PATHS", fallback="").split(",") if config.get("Dictionaries", "CMS_PATHS", fallback="") else ["/wp-config.php", "/wp-admin/", "/wp-login.php", "/wp-content/", "/configuration.php", "/administrator/", "/sites/default/settings.php", "/user/login"],
        "login_paths": config.get("Dictionaries", "LOGIN_PATHS", fallback="").split(",") if config.get("Dictionaries", "LOGIN_PATHS", fallback="") else ["/login", "/admin", "/signin", "/dashboard", "/wp-login.php", "/user/login"],
    }
    
    return settings
