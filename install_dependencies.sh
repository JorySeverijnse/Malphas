#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error.
# The exit status of a pipeline is the exit status of the last command that failed,
# or zero if no command has failed.
set -euo pipefail

# --- Distribution Detection ---
# Detects the current Linux distribution and sets package manager commands accordingly.
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID,,}" # Convert to lowercase
    # Use ID_LIKE as a fallback if ID is too specific (e.g., popos -> ubuntu)
    if [[ -z "$DISTRO_ID" || ("$DISTRO_ID" == "debian" && ${ID_LIKE:+x}) ]]; then
      DISTRO_ID="${ID_LIKE,,}"
    fi
  elif command -v lsb_release &>/dev/null; then
    DISTRO_ID=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
  elif [[ -f /etc/debian_version ]]; then
    DISTRO_ID="debian"
  elif [[ -f /etc/redhat-release || -f /etc/centos-release ]]; then
    DISTRO_ID="rhel" # Treat RHEL-likes as 'rhel' for package management
  elif [[ -f /etc/arch-release ]]; then
    DISTRO_ID="arch"
  else
    echo "Cannot reliably detect distribution! Exiting."
    exit 1
  fi

  case "$DISTRO_ID" in
  ubuntu | debian | mint)
    DISTRO_FAMILY="debian"
    INSTALL_CMD="sudo apt install -y"
    UPDATE_CMD="sudo apt update"
    GO_PACKAGE="golang-go" # Common Go package name on Debian-based systems
    ;;
  fedora | centos | rhel | almalinux | rocky)
    DISTRO_FAMILY="rhel"
    INSTALL_CMD="sudo dnf install -y"
    UPDATE_CMD="sudo dnf check-update || true" # dnf check-update returns 1 if updates are available
    GO_PACKAGE="golang"
    ;;
  arch | manjaro)
    DISTRO_FAMILY="arch"
    INSTALL_CMD="sudo pacman -S --noconfirm"
    UPDATE_CMD="sudo pacman -Syy"
    GO_PACKAGE="go"
    ;;
  *)
    echo "Unsupported distribution: $DISTRO_ID. Please install prerequisites manually. Exiting."
    exit 1
    ;;
  esac

  echo "[*] Detected distribution: ${DISTRO_ID} (Family: ${DISTRO_FAMILY})"
}

# --- Go Environment Setup ---
# Set GOBIN and add it to PATH for the current script execution.
# This ensures 'go install' works and subsequent 'command -v' checks find the newly installed Go tools.
export GOBIN="$HOME/go/bin"
export PATH="$PATH:$GOBIN"

# --- Helper Function: Install if Missing ---
# Checks if a package or command is installed and installs it using the detected package manager.
install_if_missing() {
  local pkgs=("$@")
  local pkg_name_for_install="" # Initialize for use inside the loop

  for pkg in "${pkgs[@]}"; do
    # Determine the actual package name for installation if it differs from the command name
    case "$DISTRO_FAMILY" in
    debian)
      if [[ "$pkg" == "go" ]]; then
        pkg_name_for_install="$GO_PACKAGE"
      else
        pkg_name_for_install="$pkg"
      fi
      ;;
    rhel)
      if [[ "$pkg" == "sqlmap" ]]; then
        pkg_name_for_install="python3-sqlmap" # Correct package name for RHEL-based systems
      elif [[ "$pkg" == "go" ]]; then
        pkg_name_for_install="$GO_PACKAGE"
      else
        pkg_name_for_install="$pkg"
      fi
      ;;
    arch)
      pkg_name_for_install="$pkg" # Arch package names typically match command names
      ;;
    *)
      pkg_name_for_install="$pkg" # Default for other unsupported distros
      ;;
    esac

    # Check if the command exists OR if the package is installed via system package manager
    if command -v "$pkg" &>/dev/null || dpkg -s "$pkg_name_for_install" &>/dev/null || rpm -q "$pkg_name_for_install" &>/dev/null || pacman -Q "$pkg_name_for_install" &>/dev/null; then
      echo "[✔] ${pkg} already installed."
    else
      echo "[*] Installing: ${pkg} (as ${pkg_name_for_install})..."
      if ! $INSTALL_CMD "$pkg_name_for_install"; then
        echo "[!] Failed to install ${pkg}. Please check your internet connection or package manager status."
        echo "    You might need to install ${pkg} manually."
      fi
    fi
  done
}

# Installation Functions

# Install Prerequisites
# Installs essential tools like curl, git, and Go's runtime.
install_prerequisites() {
  echo -e "\n=== Installing Prerequisites ==="
  echo "[*] Updating package lists..."
  $UPDATE_CMD || true # Allow update to fail gracefully if repos are temporarily unreachable

  case "$DISTRO_FAMILY" in
  debian)
    install_if_missing curl git "$GO_PACKAGE"
    ;;
  rhel)
    install_if_missing curl git "$GO_PACKAGE"
    ;;
  arch)
    echo "[*] AUR helper (paru/yay) might be needed for some tools not in official repos."
    install_if_missing curl git "$GO_PACKAGE" base-devel # ADDED base-devel for AUR build dependencies
    ;;
  esac
}

# Install Distro-based Tools
# Installs tools typically found in distribution repositories, like sqlmap, wpscan, and zaproxy.
# OpenVAS/GVM is handled separately for Arch due to its complexity.
install_distro_tools() {
  echo -e "\n=== Installing Tools from Distro Repositories ==="

  case "$DISTRO_FAMILY" in
  debian)
    # SQLMap is usually available.
    install_if_missing sqlmap
    echo -e "\n[!] For Debian/Ubuntu, 'wpscan' is often installed as a Ruby gem (gem install wpscan)."
    echo "    'ZAP (zaproxy)' is typically installed from its official website, a Snap package (snap install zaproxy --classic), or by adding a PPA."
    echo "    'OpenVAS/GVM' (Greenbone Vulnerability Management) is a complex suite that may require adding specific repositories or manual compilation."
    echo "    Please refer to their official documentation for installation instructions."
    ;;
  rhel)
    # SQLMap might be python3-sqlmap on RHEL.
    install_if_missing sqlmap
    echo -e "\n[!] For RHEL/CentOS/Fedora, 'wpscan' is often installed as a Ruby gem."
    echo "    'ZAP (zaproxy)' is typically installed from its official website or by adding a third-party repository."
    echo "    'OpenVAS/GVM' (Greenbone Vulnerability Management) is a complex suite that often requires specific repository additions (e.g., EPEL for some components) or manual compilation."
    echo "    Please refer to their official documentation for installation instructions."
    ;;
  arch)
    # Tools generally available in official Arch repos or easier AUR packages.
    local arch_general_tools=(sqlmap) # Only sqlmap is generally straightforward via pacman

    # Install general tools first
    for pkg in "${arch_general_tools[@]}"; do
      if ! pacman -Q "$pkg" &>/dev/null; then
        echo "[*] Attempting to install ${pkg} via pacman..."
        if $INSTALL_CMD "$pkg"; then
          echo "[✔] ${pkg} installed via pacman."
        else
          echo "[!] Failed to install ${pkg} via pacman. Manual intervention may be needed."
        fi
      else
        echo "[✔] ${pkg} already installed."
      fi
    done
    echo -e "\n[!] For Arch Linux, 'wpscan' is available in the AUR (e.g., wpscan-git)."
    echo "    'ZAP (zaproxy)' is available in the AUR (e.g., zaproxy)."
    echo "    OpenVAS/Greenbone Vulnerability Management (GVM) is a complex suite, often requiring manual installation and configuration, potentially from AUR or source, involving database setup and service management."
    echo "    Please refer to the Arch Wiki (https://wiki.archlinux.org/title/Greenbone_Vulnerability_Management) or official documentation for installation instructions for these tools."
    ;;
  esac
}

# Install Go-based Tools
# Installs various security tools written in Go, using 'go install'.
install_go_tools() {
  echo -e "\n=== Installing Go-based Tools ==="
  declare -A go_tools=(
    [nuclei]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [amass]="github.com/owasp-amass/amass/v4/...@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
    [dalfox]="github.com/hahwul/dalfox/v2@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [trufflehog]="github.com/trufflesecurity/trufflehog@latest"
    [ffuf]="github.com/ffuf/ffuf/v2@latest"
    [gospider]="github.com/jaeles-project/gospider@latest"
  )

  # Define common alternate binary names for Go tools that might be installed
  # by system package managers (e.g., httpx-toolkit for httpx).
  declare -A go_tool_alternates=(
    [httpx]="httpx-toolkit"
    [nuclei]="nuclei-bin"
    [subfinder]="subfinder-bin"
    [naabu]="naabu-bin"
  )

  for tool_cmd in "${!go_tools[@]}"; do
    local go_path="${go_tools[$tool_cmd]}"
    local alternate_cmd="" # Initialize to empty string
    local is_already_installed="false"

    # Check if an alternate command name is defined for this tool_cmd.
    # This handles cases where a tool might be packaged with a different name (e.g., `httpx-toolkit`).
    if [[ -v "go_tool_alternates[$tool_cmd]" ]]; then # Check if the key exists in the associative array
      alternate_cmd="${go_tool_alternates[$tool_cmd]}"
    fi

    # 1. Check if the exact command name is in PATH (could be Go-installed or other).
    if command -v "$tool_cmd" &>/dev/null; then
      is_already_installed="true"
    # 2. Check if an alternate command name was defined and is in PATH.
    elif [[ -n "$alternate_cmd" ]]; then # Now alternate_cmd is guaranteed to be set or empty.
      if command -v "$alternate_cmd" &>/dev/null; then
        is_already_installed="true"
      fi
    # 3. Check if the binary exists directly in GOBIN (for previous go installs not yet in main PATH).
    elif [[ -x "$GOBIN/$tool_cmd" ]]; then
      is_already_installed="true"
    fi

    if [[ "$is_already_installed" == "true" ]]; then
      echo "[✔] ${tool_cmd} already installed."
    else
      echo "[*] Installing ${tool_cmd} via go install..."
      if go install "$go_path"; then
        echo "[✔] ${tool_cmd} installed successfully."
      else
        echo "[!] Failed to install ${tool_cmd}. Check your Go installation or network connectivity."
      fi
    fi
  done
}

# Set Up Persistent Go PATH
# Ensures that the Go binary directory is permanently added to the user's PATH.
setup_persistent_gobin() {
  echo -e "\n=== Setting Up Persistent Go PATH ==="
  local gobin_dir="$HOME/go/bin" # Define the directory we're looking for
  local gobin_line bashrc zshrc fish_config config

  # Define the line to add based on the shell.
  gobin_line='export PATH="$PATH:'"$gobin_dir"'"'

  case "$SHELL" in
  */bash)
    config="$HOME/.bashrc"
    ;;
  */zsh)
    config="$HOME/.zshrc"
    ;;
  */fish)
    config="$HOME/.config/fish/config.fish"
    gobin_line='set -gx PATH $PATH '"$gobin_dir"'' # Fish syntax requires different assignment
    ;;
  *)
    echo "[!] Unknown shell: ${SHELL}. Please add ${gobin_dir} to your PATH manually."
    return
    ;;
  esac

  # First, check if gobin_dir is ALREADY in the current shell's PATH.
  # This is the most reliable check for an active PATH.
  local gobin_dir_escaped_for_path_grep=$(echo "$gobin_dir" | sed 's/\//\\\//g') # Escape for path regex
  if echo "$PATH" | command grep -qE "(^|:)${gobin_dir_escaped_for_path_grep}(:|$)"; then
    echo "[✔] Go binary path (${gobin_dir}) is already in your current shell's PATH."
    return # Exit the function, no need to modify config files.
  fi

  # Create config file if it doesn't exist.
  if [[ ! -f "$config" ]]; then
    echo "[*] Shell config ${config} not found, creating it."
    touch "$config"
  fi

  # If not in current PATH, check the config file more generally for its presence.
  # Use 'command grep' to bypass any aliases like 'rg'.
  # Simplified regex for file check: just look for the literal string within the file on any line containing 'PATH=' or 'export PATH='
  # No need to over-escape '/' for general string presence in grep -E.
  if command grep -qE "PATH=.*${gobin_dir}|\bset -gx PATH\b.*${gobin_dir}" "$config"; then
    echo "[✔] Go binary path (${gobin_dir}) appears to be configured in ${config}."
  else
    echo "[*] Adding Go binary path to ${config}."
    echo -e "\n# Go tools path\n${gobin_line}" >>"$config"
  fi
}

# Execution

# Execute the installation functions in order.
detect_distro
install_prerequisites
install_distro_tools
install_go_tools
setup_persistent_gobin

echo -e "\n[+] Installation complete! Please restart your terminal or source your shell configuration (e.g., 'source ~/.bashrc') to load the Go tools PATH and any other new settings."
