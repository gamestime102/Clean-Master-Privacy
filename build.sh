#!/bin/bash

# Clean Master Privacy - Build Script
# Usage: ./build.sh [debug|release|deb|clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo is not installed. Please install Rust first."
        exit 1
    fi
    
    if ! pkg-config --exists gtk4; then
        log_error "GTK4 development libraries not found."
        log_info "Install with: sudo apt-get install libgtk-4-dev libadwaita-1-dev"
        exit 1
    fi
    
    log_success "All dependencies found"
}

# Build debug version
build_debug() {
    log_info "Building debug version..."
    cargo build
    log_success "Debug build completed: target/debug/clean-master-privacy"
}

# Build release version
build_release() {
    log_info "Building release version..."
    cargo build --release
    log_success "Release build completed: target/release/clean-master-privacy"
}

# Build Debian package
build_deb() {
    log_info "Building Debian package..."
    
    if ! command -v cargo-deb &> /dev/null; then
        log_info "Installing cargo-deb..."
        cargo install cargo-deb
    fi
    
    cargo deb
    log_success "Debian package built: target/debian/*.deb"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    cargo clean
    log_success "Clean completed"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    cargo test
    log_success "Tests completed"
}

# Format code
format_code() {
    log_info "Formatting code..."
    cargo fmt
    log_success "Code formatted"
}

# Run clippy
run_clippy() {
    log_info "Running clippy..."
    cargo clippy -- -D warnings
    log_success "Clippy check passed"
}

# Main
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Clean Master Privacy - Build Script  ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    check_dependencies
    
    case "${1:-debug}" in
        debug)
            build_debug
            ;;
        release)
            build_release
            ;;
        deb)
            build_deb
            ;;
        clean)
            clean
            ;;
        test)
            run_tests
            ;;
        format)
            format_code
            ;;
        clippy)
            run_clippy
            ;;
        all)
            format_code
            run_clippy
            run_tests
            build_release
            build_deb
            ;;
        *)
            echo "Usage: $0 [debug|release|deb|clean|test|format|clippy|all]"
            echo ""
            echo "Commands:"
            echo "  debug    - Build debug version (default)"
            echo "  release  - Build release version"
            echo "  deb      - Build Debian package"
            echo "  clean    - Clean build artifacts"
            echo "  test     - Run tests"
            echo "  format   - Format code"
            echo "  clippy   - Run clippy linter"
            echo "  all      - Run format, clippy, test, release, and deb"
            exit 1
            ;;
    esac
    
    echo ""
    log_success "Build script completed!"
}

main "$@"
