#!/bin/bash

set -euo pipefail

# Detect Linux distro
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  DISTRO="${ID,,}"
  [[ -z "$DISTRO" && -n "$ID_LIKE" ]] && DISTRO="${ID_LIKE,,}"
else
  echo "Cannot detect distribution!"
  exit 1
fi

echo "[*] Detected distribution: $DISTRO"

# Configure GOPATH and PATH for Go tools in this session
export GOBIN="$HOME/go/bin"
export PATH="$PATH:$GOBIN"

# Helper function to install only missing system packages
install_if_missing() {
  for pkg in "$@"; do
    if ! command -v "$pkg" &>/dev/null; then
      echo "[*] Installing: $pkg"
      $INSTALL_CMD "$pkg"
    else
      echo "[✔] $pkg already installed"
    fi
  done
}

install_prerequisites() {
  echo -e "\n=== Installing prerequisites ==="
  case "$DISTRO" in
  debian | ubuntu)
    sudo apt update
    INSTALL_CMD="sudo apt install -y"
    install_if_missing curl git go
    ;;
  fedora)
    INSTALL_CMD="sudo dnf install -y"
    install_if_missing curl git golang
    ;;
  arch)
    echo "[*] Assuming paru is available for AUR support"
    INSTALL_CMD="sudo pacman -S --noconfirm"
    install_if_missing curl git go
    ;;
  *)
    echo "Unsupported distribution: $DISTRO"
    exit 1
    ;;
  esac
}

install_distro_tools() {
  echo -e "\n=== Installing tools from distro repos ==="
  case "$DISTRO" in
  debian | ubuntu)
    install_if_missing subfinder httpx naabu nuclei sqlmap wpscan zaproxy
    ;;
  fedora)
    install_if_missing subfinder httpx naabu nuclei sqlmap wpscan zaproxy
    ;;
  arch)
    AUR_PKGS=(subfinder-bin httpx-bin naabu-bin sqlmap wpscan zaproxy openvas-scanner gvm)
    for pkg in "${AUR_PKGS[@]}"; do
      if ! paru -Q "$pkg" &>/dev/null; then
        echo "[*] Installing AUR package: $pkg"
        paru -S --noconfirm "$pkg"
      else
        echo "[✔] $pkg already installed"
      fi
    done
    ;;
  esac
}

install_go_tools() {
  echo -e "\n=== Installing Go-based tools ==="
  declare -A go_tools=(
    [nuclei]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    [amass]="github.com/owasp-amass/amass/v4/...@latest"
    [dnsrecon]="github.com/darkoperator/dnsrecon@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
    [dalfox]="github.com/hahwul/dalfox/v2@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [trufflehog]="github.com/trufflesecurity/trufflehog@latest"
    [ffuf]="github.com/ffuf/ffuf/v2@latest"
    [gospider]="github.com/jaeles-project/gospider@latest"
  )

  for tool in "${!go_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null && ! [[ -x "$GOBIN/$tool" ]]; then
      echo "[*] Installing $tool via go install"
      go install "${go_tools[$tool]}"
    else
      echo "[✔] $tool already installed"
    fi
  done
}

setup_persistent_gobin() {
  echo -e "\n=== Setting up persistent Go PATH ==="
  local gobin_line bashrc zshrc fish_config config

  gobin_line='export PATH="$PATH:$HOME/go/bin"'

  case "$SHELL" in
  */bash)
    config="$HOME/.bashrc"
    ;;
  */zsh)
    config="$HOME/.zshrc"
    ;;
  */fish)
    config="$HOME/.config/fish/config.fish"
    gobin_line='set -gx PATH $PATH $HOME/go/bin'
    ;;
  *)
    echo "[!] Unknown shell: $SHELL. Please add $HOME/go/bin to your PATH manually."
    return
    ;;
  esac

  if [[ ! -f "$config" ]]; then
    echo "[*] Shell config $config not found, creating it."
    touch "$config"
  fi

  if ! grep -Fxq "$gobin_line" "$config"; then
    echo "[*] Adding Go binary path to $config"
    echo -e "\n# Go tools path\n$gobin_line" >>"$config"
  else
    echo "[✔] Go binary path already set in $config"
  fi
}

install_prerequisites
install_distro_tools
install_go_tools
setup_persistent_gobin

echo -e "\n[+] Installation complete! Please restart your terminal or source your shell config to load the Go tools PATH."
