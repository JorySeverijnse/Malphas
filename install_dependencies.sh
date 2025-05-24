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
    [[ -z "$DISTRO_ID" || "$DISTRO_ID" == "debian" && -n "$ID_LIKE" ]] && DISTRO_ID="${ID_LIKE,,}"
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

  for pkg in "${pkgs[@]}"; do
    # Check if the command exists OR if the package is installed via system package manager
    if command -v "$pkg" &>/dev/null || dpkg -s "$pkg" &>/dev/null || rpm -q "$pkg" &>/dev/null || pacman -Q "$pkg" &>/dev/null; then
      echo "[✔] ${pkg} already installed."
    else
      echo "[*] Installing: ${pkg}..."
      # Special handling for the Go package if its name differs across distros
      if [[ "$pkg" == "go" && "$GO_PACKAGE" != "go" ]]; then
        if ! $INSTALL_CMD "$GO_PACKAGE"; then
          echo "[!] Failed to install ${pkg}. Please check your internet connection or package manager status."
        fi
      else
        if ! $INSTALL_CMD "$pkg"; then
          echo "[!] Failed to install ${pkg}. Please check your internet connection or package manager status."
        fi
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
    install_if_missing curl git "$GO_PACKAGE"
    ;;
  esac
}

# Install Distro-based Tools
# Installs tools typically found in distribution repositories, like sqlmap, wpscan, zaproxy, and openvas-scanner.
install_distro_tools() {
  echo -e "\n=== Installing Tools from Distro Repositories ==="
  # These are tools that are typically well-maintained in distro repositories.
  # openvas-scanner is added here and handled specifically for Arch Linux.
  local common_distro_tools=(sqlmap wpscan zaproxy openvas-scanner)

  case "$DISTRO_FAMILY" in
  debian | rhel)
    install_if_missing "${common_distro_tools[@]}"
    ;;
  arch)
    # Separate tools that are typically in official Arch repos from those in AUR.
    local arch_official_tools=(sqlmap wpscan zaproxy)
    local arch_aur_tools=(openvas-scanner) # Explicitly mark this as an AUR candidate

    # Install official repo tools first
    for pkg in "${arch_official_tools[@]}"; do
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

    # Handle AUR specific tools like openvas-scanner
    for pkg in "${arch_aur_tools[@]}"; do
      local installed_via_aur="false"
      # Check for various common package names for OpenVAS/GVM in AUR or official repos
      if pacman -Q "$pkg" &>/dev/null ||
        (command -v paru &>/dev/null && paru -Q "$pkg" &>/dev/null) ||
        (command -v yay &>/dev/null && yay -Q "$pkg" &>/dev/null) ||
        pacman -Q "greenbone-scanner" &>/dev/null ||
        (command -v paru &>/dev/null && paru -Q "greenbone-scanner" &>/dev/null) ||
        (command -v yay &>/dev/null && yay -Q "greenbone-scanner" &>/dev/null) ||
        pacman -Q "openvas" &>/dev/null ||
        (command -v paru &>/dev/null && paru -Q "openvas" &>/dev/null) ||
        (command -v yay &>/dev/null && yay -Q "openvas" &>/dev/null); then
        echo "[✔] ${pkg} already installed (detected via pacman/AUR helper)."
        installed_via_aur="true"
      fi

      if [[ "$installed_via_aur" == "false" ]]; then
        echo "[*] Attempting to install ${pkg} (AUR) via paru/yay..."
        if command -v paru &>/dev/null; then
          if paru -S --noconfirm "$pkg"; then # Try the exact name first (e.g., openvas-scanner)
            echo "[✔] ${pkg} installed via paru."
          elif paru -S --noconfirm "greenbone-scanner"; then # Try common alternate name
            echo "[✔] greenbone-scanner installed via paru."
          elif paru -S --noconfirm "openvas"; then # Try another common alternate name
            echo "[✔] openvas installed via paru."
          else
            echo "[!] Failed to install ${pkg} via paru. Please install it manually if needed."
          fi
        elif command -v yay &>/dev/null; then
          if yay -S --noconfirm "$pkg"; then # Try the exact name first
            echo "[✔] ${pkg} installed via yay."
          elif yay -S --noconfirm "greenbone-scanner"; then # Try common alternate name
            echo "[✔] greenbone-scanner installed via yay."
          elif yay -S --noconfirm "openvas"; then # Try another common alternate name
            echo "[✔] openvas installed via yay."
          else
            echo "[!] Failed to install ${pkg} via yay. Please install it manually if needed."
          fi
        else
          echo "[!] paru or yay not found. Please install ${pkg} manually if needed."
        fi
      fi
    done
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

  # Create config file if it doesn't exist.
  if [[ ! -f "$config" ]]; then
    echo "[*] Shell config ${config} not found, creating it."
    touch "$config"
  fi

  # Check if $gobin_dir is already anywhere in a PATH definition in the config file.
  # This regex attempts to find common PATH assignment patterns and the Go binary directory.
  # The 'sed' command escapes forward slashes in gobin_dir for the regex.
  if grep -qE "PATH=.*(^|:|\s)$(echo "$gobin_dir" | sed 's/\//\\\//g')( |:|$)|\bset -gx PATH\b.*\b$(echo "$gobin_dir" | sed 's/\//\\\//g')\b" "$config"; then
    echo "[✔] Go binary path (${gobin_dir}) already set in ${config}."
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
