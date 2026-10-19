#!/bin/sh
# Installs lazyios with uv. No sudo needed.
set -e

if ! command -v uv >/dev/null 2>&1; then
    echo "installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# 3.12: some pymobiledevice3 deps have no wheels for newer Pythons and would need a C compiler
uv tool install --upgrade --python 3.12 lazyios

if [ "$(uname -s)" = "Linux" ] && ! command -v usbmuxd >/dev/null 2>&1 && [ ! -x /usr/sbin/usbmuxd ]; then
    echo
    echo "lazyios needs usbmuxd. Install it with your package manager, for example:"
    echo "  sudo apt install usbmuxd"
fi

echo
echo "done. open a new terminal and run: lazyios"
