#!/bin/bash

# STEVENXSS v1.0 - Installation Script
# Developer: STEVEN
# This script installs all dependencies and sets up the environment for STEVENXSS

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${CYAN}[ℹ] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_banner() {
    echo -e "${CYAN}"
    cat << "BANNER"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    ███████╗████████╗███████╗██╗   ██╗███████╗███╗   ██╗██╗  ██╗║
║    ██╔════╝╚══██╔══╝██╔════╝██║   ██║██╔════╝████╗  ██║╚██╗██╔╝║
║    ███████╗   ██║   █████╗  ██║   ██║█████╗  ██╔██╗ ██║ ╚███╔╝ ║
║    ╚════██║   ██║   ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║ ██╔██╗ ║
║    ███████║   ██║   ███████╗ ╚████╔╝ ███████╗██║ ╚████║██╔╝ ██╗║
║    ╚══════╝   ╚═╝   ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝║
║                                                                ║
║    🚀 WELCOME TO STEVEN WEB KIT - ENTERPRISE EDITION          ║
║    Advanced DOM XSS Scanner v1.0                              ║
║    Developer: STEVEN | Enterprise Security Tool               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root is not recommended. Continue? (y/N)"
        read -r response
        if [[ ! $response =~ ^[Yy]$ ]]; then
            print_info "Exiting..."
            exit 1
        fi
    fi
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [[ -f /etc/debian_version ]]; then
            echo "debian"
        elif [[ -f /etc/redhat-release ]]; then
            echo "redhat"
        elif [[ -f /etc/arch-release ]]; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
install_system_deps() {
    local os=$1
    print_info "Installing system dependencies for $os..."
    
    case $os in
        "debian"|"ubuntu")
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv curl wget git \
                build-essential libssl-dev libffi-dev python3-dev \
                libnss3-dev libnspr4-dev libatk-bridge2.0-dev libgtk-3-dev \
                libxss-dev libasound2-dev
            ;;
        "redhat"|"centos"|"fedora")
            if command_exists dnf; then
                sudo dnf install -y python3 python3-pip python3-venv curl wget git \
                    gcc-c++ make openssl-devel libffi-devel python3-devel \
                    nss-devel nspr-devel atk-devel gtk3-devel \
                    libXScrnSaver-devel alsa-lib-devel
            else
                sudo yum install -y python3 python3-pip curl wget git \
                    gcc-c++ make openssl-devel libffi-devel python3-devel \
                    nss-devel nspr-devel atk-devel gtk3-devel \
                    libXScrnSaver-devel alsa-lib-devel
            fi
            ;;
        "arch")
            sudo pacman -Sy --noconfirm python python-pip curl wget git \
                base-devel openssl libffi nss nspr atk gtk3 \
                libxss alsa-lib
            ;;
        "macos")
            if ! command_exists brew; then
                print_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install python3 curl wget git
            ;;
        *)
            print_warning "Unknown OS. Please install Python 3.8+, pip, and virtualenv manually."
            ;;
    esac
}

# Check Python version
check_python() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_VERSION=$(python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || echo "0")
        PYTHON_CMD="python"
    else
        print_error "Python not found. Please install Python 3.8 or higher."
        exit 1
    fi

    # Check if Python version is sufficient
    if [[ $(echo "$PYTHON_VERSION >= 3.8" | bc -l 2>/dev/null) -eq 1 ]] || [[ "$PYTHON_VERSION" == "3.8"* ]] || [[ "$PYTHON_VERSION" == "3.9"* ]] || [[ "$PYTHON_VERSION" == "3.10"* ]] || [[ "$PYTHON_VERSION" == "3.11"* ]] || [[ "$PYTHON_VERSION" == "3.12"* ]]; then
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3.8 or higher is required. Found Python $PYTHON_VERSION"
        exit 1
    fi
}

# Create virtual environment
create_venv() {
    print_info "Creating Python virtual environment..."
    
    if [[ -d "venv" ]]; then
        print_warning "Virtual environment already exists. Recreate? (y/N)"
        read -r response
        if [[ $response =~ ^[Yy]$ ]]; then
            rm -rf venv
        else
            return 0
        fi
    fi
    
    $PYTHON_CMD -m venv venv
    
    if [[ -f "venv/bin/activate" ]]; then
        source venv/bin/activate
        print_success "Virtual environment activated"
    elif [[ -f "venv/Scripts/activate" ]]; then
        source venv/Scripts/activate
        print_success "Virtual environment activated"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi
}

# Upgrade pip
upgrade_pip() {
    print_info "Upgrading pip..."
    pip install --upgrade pip
    print_success "Pip upgraded to latest version"
}

# Install Python dependencies
install_python_deps() {
    print_info "Installing Python dependencies..."
    
    # Create requirements file
    cat > requirements.txt << 'EOF'
aiohttp>=3.8.0
playwright>=1.40.0
reportlab>=4.0.0
requests>=2.31.0
urllib3>=2.0.0
colorama>=0.4.6
beautifulsoup4>=4.12.0
lxml>=4.9.0
cryptography>=41.0.0
psutil>=5.9.0
tqdm>=4.65.0
pyOpenSSL>=23.0.0
EOF

    pip install -r requirements.txt
    
    # Install Playwright browsers
    print_info "Installing Playwright browsers..."
    python -m playwright install
    python -m playwright install-deps
    
    print_success "All Python dependencies installed"
}

# Install Chromium manually if needed
install_chromium_manual() {
    local os=$1
    print_info "Installing Chromium for Playwright..."
    
    case $os in
        "debian"|"ubuntu")
            sudo apt install -y chromium-browser chromium-chromedriver
            ;;
        "redhat"|"centos"|"fedora")
            if command_exists dnf; then
                sudo dnf install -y chromium chromium-driver
            else
                sudo yum install -y chromium chromium-driver
            fi
            ;;
        "arch")
            sudo pacman -Sy --noconfirm chromium
            ;;
        "macos")
            brew install --cask chromium
            ;;
    esac
}

# Create configuration files
create_config_files() {
    print_info "Creating configuration files..."
    
    # Create payloads directory and sample payload file
    mkdir -p payloads
    
    # Create sample XSS payloads file
    cat > payloads/xss-payloads.txt << 'EOF'
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
</script><script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src=javascript:alert('XSS')>
javascript:alert('XSS')
" autofocus onfocus=alert('XSS')//
' autofocus onfocus=alert('XSS')//
<math><mi//xlink:href="javascript:alert('XSS')">CLICK
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
<video><source onerror=alert('XSS')>
<audio><source onerror=alert('XSS')>
EOF

    # Create sample headers file
    cat > headers.json << 'EOF'
{
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}
EOF

    print_success "Configuration files created"
}

# Set file permissions
set_permissions() {
    print_info "Setting file permissions..."
    
    chmod +x stevenxss.py
    
    if [[ -f "venv/bin/python" ]]; then
        chmod +x venv/bin/python
    fi
    
    if [[ -f "venv/Scripts/python.exe" ]]; then
        chmod +x venv/Scripts/python.exe
    fi
    
    print_success "File permissions set"
}

# Create run script
create_run_script() {
    print_info "Creating run script..."
    
    cat > run_stevenxss.sh << 'EOF'
#!/bin/bash

# STEVENXSS Runner Script
# This script activates the virtual environment and runs STEVENXSS

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Activate virtual environment
if [[ -f "$SCRIPT_DIR/venv/bin/activate" ]]; then
    source "$SCRIPT_DIR/venv/bin/activate"
elif [[ -f "$SCRIPT_DIR/venv/Scripts/activate" ]]; then
    source "$SCRIPT_DIR/venv/Scripts/activate"
else
    echo "Error: Virtual environment not found. Please run install.sh first."
    exit 1
fi

# Run STEVENXSS
python "$SCRIPT_DIR/stevenxss.py" "$@"
EOF

    chmod +x run_stevenxss.sh
    
    print_success "Run script created: ./run_stevenxss.sh"
}

# Test installation
test_installation() {
    print_info "Testing installation..."
    
    # Test Python imports
    if python -c "import aiohttp, playwright, reportlab, requests, urllib3, colorama, bs4, lxml, cryptography, psutil, tqdm, OpenSSL" &>/dev/null; then
        print_success "All Python imports successful"
    else
        print_error "Some Python imports failed"
        return 1
    fi
    
    # Test Playwright
    if python -c "from playwright.sync_api import sync_playwright; sync_playwright().start().stop()" &>/dev/null; then
        print_success "Playwright test successful"
    else
        print_warning "Playwright test failed, but installation may still work"
    fi
    
    # Test main script
    if python stevenxss.py --help &>/dev/null; then
        print_success "STEVENXSS script test successful"
    else
        print_error "STEVENXSS script test failed"
        return 1
    fi
    
    return 0
}

# Display usage information
show_usage() {
    print_info "STEVENXSS v1.0 Installation Complete!"
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./run_stevenxss.sh -u <URL> -f payloads/xss-payloads.txt"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  ./run_stevenxss.sh -u https://example.com -f payloads/xss-payloads.txt"
    echo "  ./run_stevenxss.sh -u https://example.com -f payloads/xss-payloads.txt --dom"
    echo "  ./run_stevenxss.sh -u https://example.com -f payloads/xss-payloads.txt -m POST -d 'param1=value1&param2=value2'"
    echo ""
    echo -e "${GREEN}Important Files:${NC}"
    echo "  • stevenxss.py - Main scanner script"
    echo "  • run_stevenxss.sh - Runner script (use this)"
    echo "  • payloads/xss-payloads.txt - Sample payloads"
    echo "  • headers.json - Sample headers"
    echo ""
    echo -e "${YELLOW}Note: Always use './run_stevenxss.sh' to run the scanner${NC}"
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        print_error "Installation failed. Cleaning up..."
        if [[ -d "venv" ]]; then
            rm -rf venv
        fi
        if [[ -f "requirements.txt" ]]; then
            rm -f requirements.txt
        fi
    fi
}

# Main installation function
main() {
    trap cleanup EXIT
    
    print_banner
    print_info "Starting STEVENXSS v1.0 installation..."
    
    # Check if not running as root
    check_root
    
    # Detect OS
    OS=$(detect_os)
    print_info "Detected OS: $OS"
    
    # Check Python
    check_python
    
    # Install system dependencies
    install_system_deps "$OS"
    
    # Create virtual environment
    create_venv
    
    # Upgrade pip
    upgrade_pip
    
    # Install Python dependencies
    install_python_deps
    
    # Install Chromium if needed
    install_chromium_manual "$OS"
    
    # Create configuration files
    create_config_files
    
    # Set permissions
    set_permissions
    
    # Create run script
    create_run_script
    
    # Test installation
    if test_installation; then
        print_success "🎉 STEVENXSS v1.0 installed successfully!"
        show_usage
    else
        print_error "❌ Installation completed with some errors. Please check the output above."
        exit 1
    fi
}

# Run main function
main "$@"