{
  pkgs,
  lib,
  stdenvNoCC,
  buildFHSEnv,
  makeDesktopItem,
  symlinkJoin,
  bash,
  coreutils,
  pciutils,
  squashfsTools,
  steam-unwrapped,
  vulkan-loader,
}:

# Container layering:
# - FHS set up here: base FHS tree with minimal set of arm64 libraries
# - inside of FEX: overlays FEX RootFS on base FHS
# - pressure-vessel: FHS with Steam Linux Runtime overlay (???); FEX rootfs mounted at something like /run/pressure-vessel/...
#   - PV is launched from FEX BUT FEX_ROOTFS is changed!
#   - PV looks for Vulkan icd files in parent container
# - FEX in pressure-vessel: overlays FEX RootFS on PV FHS

let
  fexRootFS = import ./rootfs.nix { inherit pkgs; };

  rootfsTarget = "/usr/share/fex-emu/RootFS";

  # /usr/share subdirs bound from host (same path inside and outside the sandbox).
  # Each gets a matching mkdir in extraBuildCommands so bwrap has a mount point
  # in the read-only FHS overlay at /usr.
  usrShareBinds = [
    "icons" # XCursor themes (e.g. DMZ-White on KDE)
    "pixmaps" # legacy app icons
    "fonts" # host font rendering / CJK glyphs in Steam UI
    "themes" # GTK themes for Steam's file picker / system dialogs
    "mime" # xdg-mime database (Steam registers steam:// handlers)
    "applications" # .desktop files for xdg-open
    "X11" # keyboard layouts (SDL2 reads xkb data directly)
  ];

  # /usr/share subdirs supplied by GPU drivers. Bound twice in extraBwrapArgs:
  # first from mesa (cross-host fallback), then from /run/opengl-driver
  # (NixOS hardware.graphics output, takes priority when present).
  graphicsShareBinds = [
    "vulkan" # Vulkan ICDs
    "glvnd" # GL Vendor-Neutral Dispatch config
    "drirc.d" # DRI driver config / per-app overrides
  ];

  # Extract Steam bootstrap files at build time from steam-unwrapped source
  # Raw extraction preserves generic shebangs (no patchShebangs),
  # which is required for running under FEX's x86 bash
  steamBootstrap = stdenvNoCC.mkDerivation {
    name = "steam-bootstrap-${steam-unwrapped.version}";
    inherit (steam-unwrapped) src;
    dontBuild = true;
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/steam-launcher"
      cp bin_steam.sh bootstraplinux_ubuntu12_32.tar.xz steam_subscriber_agreement.txt \
        "$out/steam-launcher/"
      runHook postInstall
    '';
  };

  desktopItem = makeDesktopItem {
    name = "steam-fex";
    desktopName = "Steam (FEX)";
    comment = "Steam on ARM64 via FEX-Emu";
    exec = "steam-fex %U";
    icon = "steam";
    categories = [
      "Game"
      "Network"
    ];
    mimeTypes = [
      "x-scheme-handler/steam"
      "x-scheme-handler/steamlink"
    ];
  };

  # Wrapper that performs preflight checks before entering the FHS env.
  # These checks must run *outside* bwrap, since bwrap arg expansion
  # fails if e.g. FEX_ROOTFS is unset.
  preflightChecks = ''
    if ! command -v FEXBash &>/dev/null; then
      echo "error: FEXBash not found in PATH" >&2
      exit 1
    fi
    echo "FEX: $(command -v FEX)"

    # Without /run/opengl-driver we fall back to bundled mesa from targetPkgs.
    # Mesa can't drive proprietary nvidia, so refuse early if nvidia.ko is loaded.
    if [ ! -e /run/opengl-driver ]; then
      if [ -e /proc/driver/nvidia ]; then
        echo "error: proprietary NVIDIA driver detected, but /run/opengl-driver is missing." >&2
        echo "       Bundled mesa fallback can't drive nvidia hardware." >&2
        echo "       On NixOS, enable hardware.graphics.enable to populate it." >&2
        exit 1
      fi
      echo "info: /run/opengl-driver missing; using bundled mesa Vulkan drivers." >&2
    fi
  '';

  launcher = buildFHSEnv {
    name = "steam-fex";

    targetPkgs = pkgs: [
      pciutils
      # The RootFS set up by pressure-vessel for FEX is based on our provided RootFS.
      # Notably, /usr/share/vulkan/icd.d from the host (i.e. our FHS env) is checked
      # for aarch64 drivers, which PV will prioritize over the RootFS-provided x86 ones.
      vulkan-loader
      # libGL.so for CEF, plus mesa's Vulkan/glvnd/drirc.d files as a cross-host
      # fallback when /run/opengl-driver isn't present. Driver .so paths in the
      # ICDs are absolute /nix/store paths, so /nix being bound is enough.
      pkgs.mesa
    ];

    # Reserve mount points in the FHS overlay for the bwrap binds below.
    # /usr inside the sandbox is a read-only Nix store path, so destination
    # directories must already exist in the overlay or bwrap can't bind onto them.
    # graphicsShareBinds mount points come from pkgs.mesa in targetPkgs.
    extraBuildCommands = ''
      mkdir -p "$out${rootfsTarget}"
      for d in ${lib.concatStringsSep " " usrShareBinds}; do
        mkdir -p "$out/usr/share/$d"
      done
    '';

    extraBwrapArgs = [
      "--ro-bind"
      "${fexRootFS}"
      rootfsTarget
      "--setenv"
      "FEX_ROOTFS"
      rootfsTarget
      "--setenv"
      "PRESSURE_VESSEL_FILESYSTEMS_RO"
      "/nix:/run/opengl-driver"
      "--setenv"
      "SDL_AUDIODRIVER"
      "pulseaudio"
      "--setenv"
      "LC_ALL"
      "C.UTF-8"
      "--setenv"
      "LANG"
      "C.UTF-8"
      # GI typelibs so x86 Python finds Gtk/GLib/etc. (steam-runtime-launch-options).
      "--setenv"
      "GI_TYPELIB_PATH"
      "${rootfsTarget}/usr/lib64/girepository-1.0"
    ]
    # Mirror selected host /usr/share subdirs at the same path inside the sandbox.
    ++ lib.concatMap (d: [
      "--ro-bind-try"
      "/usr/share/${d}"
      "/usr/share/${d}"
    ]) usrShareBinds
    # Graphics config: layer mesa as the cross-host fallback, then NixOS's
    # /run/opengl-driver on top. bwrap applies binds in order; later wins.
    ++ lib.concatMap (d: [
      "--ro-bind-try"
      "${pkgs.mesa}/share/${d}"
      "/usr/share/${d}"
    ]) graphicsShareBinds
    ++ lib.concatMap (d: [
      "--ro-bind-try"
      "/run/opengl-driver/share/${d}"
      "/usr/share/${d}"
    ]) graphicsShareBinds;

    runScript = lib.getExe (
      stdenvNoCC.mkDerivation {
        name = "steam-fex-launch";
        dontUnpack = true;
        dontBuild = true;
        installPhase = ''
          mkdir -p $out/bin
          cat > $out/bin/steam-fex-launch << 'SCRIPT'
          #!/bin/bash
          set -euo pipefail

          cat $HOME/.config/fex-emu/Config.json

          # --- Steam bootstrap ---
          data_dir="''${XDG_DATA_HOME:-$HOME/.local/share}/steam-fex"
          marker="$data_dir/bootstrap-installed"

          if [[ ! -f "$marker" || ! -f "$data_dir/steam-launcher/bin_steam.sh" ]]; then
            echo "Setting up Steam bootstrap..."
            mkdir -p "$data_dir"
            cp -a ${steamBootstrap}/steam-launcher "$data_dir/"
            echo "ok" > "$marker"
            echo "Steam bootstrap ready."
          fi

          # --- Launch via FEXBash ---
          uid=$(id -u)
          export PULSE_SERVER="unix:/run/user/$uid/pulse/native"

          if [[ "''${1:-}" == "--shell" ]]; then
            echo "Opening FEXBash shell..."
            shift
            # exec FEXBash "$@"
            exec "$@"
          fi

          steam_args="-cef-force-occlusion''${*:+ $*}"
          echo "Launching Steam via FEX..."
          exec FEXBash -c "\
            exec bash $data_dir/steam-launcher/bin_steam.sh $steam_args"
          SCRIPT
          chmod +x $out/bin/steam-fex-launch
        '';
      }
    );

    meta = {
      description = "Steam launcher for NixOS on ARM64 via FEX-Emu";
      license = lib.licenses.mit;
      platforms = [ "aarch64-linux" ];
    };
  };
in
symlinkJoin {
  name = "steam-fex";
  paths = [
    launcher
    desktopItem
  ];
  postBuild = ''
    mkdir -p "$out/share"
    ln -s ${steam-unwrapped}/share/icons "$out/share/icons"
  ''
  + lib.optionalString (preflightChecks != "") ''
    mv "$out/bin/steam-fex" "$out/bin/.steam-fex-wrapped"
    {
      echo '#!${bash}/bin/bash'
      cat <<'WRAPPER'
    set -euo pipefail
    ${preflightChecks}
    exec "$(dirname "$(readlink -f "$0")")/.steam-fex-wrapped" "$@"
    WRAPPER
    } > "$out/bin/steam-fex"
    chmod +x "$out/bin/steam-fex"
  '';
  inherit (launcher) meta;
}
