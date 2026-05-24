#!/usr/bin/env bash
#
# Launch wrapper for running x86 Steam under FEX on NixOS.
#
# Usage:
#   nix develop -c ./Data/nix/run_steam.sh [steam args...]
#
# This sets up a suitable environment so that scripts using
# #!/bin/bash or #!/usr/bin/env bash shebangs resolve to the
# x86 binaries from the FEX rootfs rather than native aarch64
# ones from the nix store.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Locate FEX binary
FEX="${FEX:-$REPO_ROOT/build/install/bin/FEX}"
if [[ ! -x "$FEX" ]]; then
    echo "error: FEX binary not found at $FEX" >&2
    echo "Build FEX first or set FEX= to the correct path." >&2
    exit 1
fi

if [[ -z "${FEX_ROOTFS:-}" ]]; then
    echo "error: FEX_ROOTFS is not set. Run this from 'nix develop'." >&2
    exit 1
fi

# Locate steam.sh
STEAM_SH="${1:-}"
if [[ -z "$STEAM_SH" ]]; then
    # Try common locations
    for candidate in \
        "$HOME/.steam/root/steam.sh" \
        "$HOME/.local/share/Steam/steam.sh" \
        "$HOME/.steam/steam/steam.sh"; do
        if [[ -f "$candidate" ]]; then
            STEAM_SH="$candidate"
            break
        fi
    done
    if [[ -z "$STEAM_SH" ]]; then
        echo "error: Could not find steam.sh. Pass the path as first argument." >&2
        exit 1
    fi
else
    shift
fi

# Prepend standard FHS directories to PATH.
#
# Under FEX, paths like /bin/bash and /usr/bin/env resolve through the rootfs
# overlay to x86 binaries. On the NixOS host these directories don't exist (or
# are empty), so prepending them is harmless outside of FEX.
#
# Without this, #!/usr/bin/env bash finds the native aarch64 bash from the nix
# store first, causing FEX to hand off execution to the host kernel. From that
# point on, #!/bin/bash shebangs fail (NixOS has no /bin/bash) and x86 binaries
# fail with "Exec format error" (no binfmt_misc).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Steam expects a variety of FHS paths for its runtime. Most are already
# provided by the FEX rootfs, but we set some environment overrides just
# in case the rootfs is minimal.
export STEAM_RUNTIME=1

# Prevent steam from complaining about missing 32-bit libraries that are
# actually present in the rootfs but not discoverable via the host's ldconfig.
export STEAM_RUNTIME_PREFER_HOST_LIBRARIES=0

# Enable extended Steam runtime logging for debugging
export SRT_LOG="${SRT_LOG:-debug}"

# Run steam.sh through FEX's x86 bash directly (not via -c) so that bash
# interprets the script in-process rather than fork+exec'ing through the
# shebang, which would go through #!/usr/bin/env resolution again.
exec "$FEX" /bin/bash "$STEAM_SH" "$@"
