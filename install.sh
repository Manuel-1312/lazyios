#!/bin/sh
# Installs lazyios with uv. No sudo needed.
set -e

if ! command -v uv >/dev/null 2>&1; then
    echo "installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

uv tool install --upgrade https://github.com/Manuel-1312/lazyios/archive/refs/heads/main.zip

if [ "$(uname -s)" = "Linux" ] && ! command -v usbmuxd >/dev/null 2>&1 && [ ! -x /usr/sbin/usbmuxd ]; then
    echo
    echo "lazyios needs usbmuxd. Install it with your package manager, for example:"
    echo "  sudo apt install usbmuxd"
fi

echo
echo "done. open a new terminal and run: lazyios"
