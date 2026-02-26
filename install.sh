#!/bin/sh
set -e

REPO="raghavpillai/mosh-buddy"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

main() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
    esac

    case "$os" in
        linux|darwin) ;;
        *) echo "Unsupported OS: $os" >&2; exit 1 ;;
    esac

    # Get latest release tag
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)"
    if [ -z "$tag" ]; then
        echo "Failed to fetch latest release" >&2
        exit 1
    fi

    url="https://github.com/${REPO}/releases/download/${tag}/mb-${os}-${arch}"
    echo "Downloading mb ${tag} for ${os}/${arch}..."

    mkdir -p "$INSTALL_DIR"
    curl -fsSL "$url" -o "${INSTALL_DIR}/mb"
    chmod +x "${INSTALL_DIR}/mb"

    echo "Installed mb to ${INSTALL_DIR}/mb"

    # Check if INSTALL_DIR is in PATH
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo ""
            echo "Add ${INSTALL_DIR} to your PATH:"
            echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            ;;
    esac

    # Offer mosh alias
    echo ""
    echo "To use mb automatically when you run mosh, add this alias:"
    echo "  alias mosh='mb connect'"
    echo ""
    echo "Done."
}

main
