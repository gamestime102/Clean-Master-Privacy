#!/bin/bash

# Clean Master Privacy - Installation Script
# Usage: ./install.sh [--system|--user|--uninstall]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="clean-master-privacy"
APP_VERSION="5.0.0"
DESKTOP_FILE="assets/clean-master-privacy.desktop"
ICON_FILE="assets/icon.png"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VERSION"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y \
                libgtk-4-1 \
                libadwaita-1-0 \
                libssl3 \
                pkg-config
            ;;
        fedora)
            sudo dnf install -y \
                gtk4 \
                libadwaita \
                openssl \
                pkgconf
            ;;
        arch|manjaro)
            sudo pacman -S --needed \
                gtk4 \
                libadwaita \
                openssl \
                pkgconf
            ;;
        *)
            log_warning "Unknown distribution. Please install GTK4 and Libadwaita manually."
            ;;
    esac
    
    log_success "Dependencies installed"
}

# Build the application
build_app() {
    log_info "Building Clean Master Privacy..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo is not installed."
        log_info "Install Rust from: https://rustup.rs/"
        exit 1
    fi
    
    cargo build --release
    
    log_success "Build completed"
}

# Install system-wide
install_system() {
    log_info "Installing system-wide (requires sudo)..."
    
    # Install binary
    sudo cp "target/release/$APP_NAME" "/usr/local/bin/"
    sudo chmod +x "/usr/local/bin/$APP_NAME"
    
    # Install desktop file
    if [ -f "$DESKTOP_FILE" ]; then
        sudo cp "$DESKTOP_FILE" "/usr/share/applications/"
    fi
    
    # Install icon
    if [ -f "$ICON_FILE" ]; then
        sudo mkdir -p "/usr/share/icons/hicolor/256x256/apps"
        sudo cp "$ICON_FILE" "/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png"
    fi
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        sudo update-desktop-database
    fi
    
    log_success "System-wide installation completed"
}

# Install for current user only
install_user() {
    log_info "Installing for current user..."
    
    # Create directories
    mkdir -p "$HOME/.local/bin"
    mkdir -p "$HOME/.local/share/applications"
    mkdir -p "$HOME/.local/share/icons/hicolor/256x256/apps"
    
    # Install binary
    cp "target/release/$APP_NAME" "$HOME/.local/bin/"
    chmod +x "$HOME/.local/bin/$APP_NAME"
    
    # Install desktop file
    if [ -f "$DESKTOP_FILE" ]; then
        cp "$DESKTOP_FILE" "$HOME/.local/share/applications/"
    fi
    
    # Install icon
    if [ -f "$ICON_FILE" ]; then
        cp "$ICON_FILE" "$HOME/.local/share/icons/hicolor/256x256/apps/$APP_NAME.png"
    fi
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database "$HOME/.local/share/applications"
    fi
    
    # Check if ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        log_warning "$HOME/.local/bin is not in your PATH"
        log_info "Add the following to your ~/.bashrc or ~/.zshrc:"
        log_info 'export PATH="$HOME/.local/bin:$PATH"'
    fi
    
    log_success "User installation completed"
}

# Uninstall
uninstall() {
    log_info "Uninstalling Clean Master Privacy..."
    
    # Remove system-wide files
    if [ -f "/usr/local/bin/$APP_NAME" ]; then
        sudo rm -f "/usr/local/bin/$APP_NAME"
    fi
    
    if [ -f "/usr/share/applications/$APP_NAME.desktop" ]; then
        sudo rm -f "/usr/share/applications/$APP_NAME.desktop"
    fi
    
    if [ -f "/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png" ]; then
        sudo rm -f "/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png"
    fi
    
    # Remove user files
    rm -f "$HOME/.local/bin/$APP_NAME"
    rm -f "$HOME/.local/share/applications/$APP_NAME.desktop"
    rm -f "$HOME/.local/share/icons/hicolor/256x256/apps/$APP_NAME.png"
    
    # Remove data directory
    rm -rf "$HOME/.local/share/$APP_NAME"
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        sudo update-desktop-database 2>/dev/null || true
        update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
    fi
    
    log_success "Uninstallation completed"
}

# Print usage
print_usage() {
    echo "Clean Master Privacy - Installation Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --system      Install system-wide (requires sudo)"
    echo "  --user        Install for current user only (default)"
    echo "  --uninstall   Remove Clean Master Privacy"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --system     # Install system-wide"
    echo "  $0 --user       # Install for current user"
    echo "  $0 --uninstall  # Uninstall"
}

# Main
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Clean Master Privacy - Installer     ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    case "${1:---user}" in
        --system)
            detect_os
            install_dependencies
            build_app
            install_system
            ;;
        --user)
            detect_os
            build_app
            install_user
            ;;
        --uninstall)
            uninstall
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
    
    echo ""
    log_success "Installation script completed!"
    echo ""
    echo "You can now run: $APP_NAME"
}

main "$@"
