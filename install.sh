#!/usr/bin/env bash
set -e

# purl installer script

PURL_BANNER="
 ____  _   _ ____  _
|  _ \| | | |  _ \| |
| |_) | | | | |_) | |
|  __/| |_| |  _ <| |___
|_|    \___/|_| \_\_____|

"

echo "$PURL_BANNER"
echo "purl installer"
echo ""

REPO="stripe/purl"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="purl"

detect_platform() {
    local platform="$(uname -s | tr '[:upper:]' '[:lower:]')"

    case "${platform}" in
        linux*)     PLATFORM="linux" ;;
        darwin*)    PLATFORM="darwin" ;;
        *)
            echo "Error: Unsupported platform '${platform}'"
            exit 1
            ;;
    esac
}

detect_arch() {
    local arch="$(uname -m)"

    case "${arch}" in
        x86_64|amd64)
            if [ "$PLATFORM" = "darwin" ]; then
                # No x86_64 macOS build; use arm64 binary via Rosetta 2
                ARCH="arm64"
            else
                ARCH="amd64"
            fi
            ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)
            echo "Error: Unsupported architecture '${arch}'"
            exit 1
            ;;
    esac
}

get_latest_release() {
    echo "Fetching latest release..."
    LATEST_RELEASE=$(curl --silent "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$LATEST_RELEASE" ]; then
        echo "Error: Could not fetch latest release"
        exit 1
    fi

    echo "Latest version: ${LATEST_RELEASE}"
}

install_purl() {
    local download_url="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/purl-${PLATFORM}-${ARCH}"
    local tmp_file="/tmp/${BINARY_NAME}"

    echo ""
    echo "Downloading purl..."
    echo "URL: ${download_url}"

    if ! curl -L --progress-bar "${download_url}" -o "${tmp_file}"; then
        echo "Error: Download failed"
        exit 1
    fi

    echo ""
    echo "Making binary executable..."
    chmod +x "${tmp_file}"

    echo "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."

    if mv "${tmp_file}" "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null; then
        echo "Installation successful!"
    elif sudo mv "${tmp_file}" "${INSTALL_DIR}/${BINARY_NAME}"; then
        echo "Installation successful!"
    else
        echo "Error: Failed to install to ${INSTALL_DIR}"
        echo "Try running with sudo or install manually"
        exit 1
    fi
}

verify_installation() {
    echo ""
    if command -v purl >/dev/null 2>&1; then
        echo "purl is installed and available in PATH"
        echo ""
        purl --version
    else
        echo "purl was installed but is not in PATH"
        echo "Make sure ${INSTALL_DIR} is in your PATH"
    fi
}

main() {
    detect_platform
    detect_arch
    get_latest_release
    install_purl
    verify_installation

    echo ""
    echo "Installation complete!"
    echo ""
    echo "Get started:"
    echo "  purl wallet add    # Configure your wallets"
    echo "  purl --help        # Show all options"
    echo ""
    echo "Documentation:"
    echo "  https://github.com/${REPO}"
    echo ""
}

main
