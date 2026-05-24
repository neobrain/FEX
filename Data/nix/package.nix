# Nix package for FEX (use via flake: nix build .#fex)
{
  pkgs ? import <nixpkgs> { },
  enableConfigUI ? true,
  enableLibraryForwarding ? true,
  gitRev ? "0000000000000000000000000000000000000000",
}:

let
  libForwardingShell = import ./LibraryForwarding/shell.nix { inherit pkgs; };
  rootfs = import ./rootfs.nix { inherit pkgs; };

  # Shared with shell.nix via passthru so the dev shell inherits the same values.
  sharedEnv = {
    # Point CMake at ClangConfig.cmake without adding unwrapped clang to PATH
    Clang_DIR = pkgs.lib.optionalString enableLibraryForwarding "${pkgs.libclang.dev}/lib/cmake/clang";

    # Point thunkgen to base C/C++ headers
    THUNKGEN_EXTRA_FLAGS = builtins.concatStringsSep " " [
      (builtins.readFile "${pkgs.llvmPackages.stdenv.cc}/nix-support/libc-cflags")
      (builtins.readFile "${pkgs.llvmPackages.stdenv.cc}/nix-support/libcxx-cxxflags")
    ];
  };
in
pkgs.clangStdenv.mkDerivation {
  name = "fex";
  src = ../../.;

  nativeBuildInputs =
    with pkgs;
    [
      cmake
      ninja
      nasm
      pkg-config
      python3Packages.packaging
      llvmPackages.bintools
      makeWrapper
    ]
    ++ pkgs.lib.optionals enableConfigUI [ pkgs.qt6.wrapQtAppsHook ];

  buildInputs =
    with pkgs;
    [
      catch2_3
      fmt
      range-v3
      unordered_dense
      xxHash
      tracy_0_12
    ]
    ++ pkgs.lib.optionals enableConfigUI [
      qt6.qtbase
      qt6.qtdeclarative
      qt6.qtwayland
    ]
    ++ pkgs.lib.optionals enableLibraryForwarding [
      openssl
      libclang.lib
      libllvm.dev
      libXrandr
      alsa-lib

      # Runtime dependencies (dlopened by FEX)
      libdrm
      vulkan-loader
      wayland
      libglvnd
    ];

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    "-DBUILD_THUNKS=${if enableLibraryForwarding then "ON" else "OFF"}"
    "-DBUILD_FEXCONFIG=${if enableConfigUI then "ON" else "OFF"}"
    "-DOVERRIDE_HASH=${gitRev}"
    "-DOVERRIDE_VERSION=FEX-local"
  ];

  # FEX_CMAKE_TOOLCHAINS is a space-separated string of -D flags pointing at
  # the X86_32/X86_64 cross toolchains and dev rootfs.
  preConfigure = pkgs.lib.optionalString enableLibraryForwarding ''
    cmakeFlagsArray+=(${libForwardingShell.FEX_CMAKE_TOOLCHAINS})
  '';

  env = sharedEnv;

  # Force ThunkHostLibs/ThunkGuestLibs to the build-time-baked install paths
  # (LAYER_TOP, highest priority). A user Config.json pinning these to a stale
  # nix-store path of an older FEX build would otherwise abort startup in
  # FileManager::SetupOverlay.
  postPatch = ''
    substituteInPlace FEXCore/Source/Interface/Config/Config.cpp \
      --replace-fail \
        ''$'void ReloadMetaLayer() {\n  Meta->Load();' \
        ''$'void ReloadMetaLayer() {\n  Meta->Load();\n  Meta->Set(FEXCore::Config::CONFIG_THUNKHOSTLIBS, detail::THUNKHOSTLIBS);\n  Meta->Set(FEXCore::Config::CONFIG_THUNKGUESTLIBS, detail::THUNKGUESTLIBS);'
  '';

  # Install a default Config.json pointing at the bundled RootFS so the
  # installed binaries work out of the box without further user setup.
  postInstall = ''
    mkdir -p $out/share/fex-emu
    cat > $out/share/fex-emu/Config.json <<EOF
    {
      "Config": {
        "RootFS": "${rootfs}"
      }
    }
    EOF
  '';

  # wrapQtAppsHook otherwise wraps every executable in $out/bin; we only want FEXConfig wrapped.
  dontWrapQtApps = true;

  # stdenv's patchELF fixup runs `patchelf --shrink-rpath`, which drops rpath
  # entries whose dirs don't contain a DT_NEEDED library. The host thunks
  # (libvulkan-host.so etc.) dlopen their targets at runtime, so libvulkan.so.1,
  # libdrm.so.2, libasound.so.2, libwayland-client.so.0 and friends never appear
  # in DT_NEEDED and the carefully-set rpaths get stripped. Skip the shrink to
  # preserve them. Closure impact is zero — the relevant paths are already
  # transitively pulled in via Qt/FEXConfig.
  dontPatchELF = true;

  postFixup = ''
    # FEXRootFSFetcher shells out to unsquashfs / mksquashfs / mkfs.erofs
    wrapProgram $out/bin/FEXRootFSFetcher \
      --prefix PATH : ${
        pkgs.lib.makeBinPath [
          pkgs.erofs-utils
          pkgs.squashfsTools
          pkgs.squashfuse
        ]
      }
  ''
  + pkgs.lib.optionalString enableConfigUI ''
    wrapQtApp $out/bin/FEXConfig
  '';

  passthru = {
    inherit rootfs;
    env = sharedEnv;
  };

  meta.description = "Emulator executables for Linux applications";
}
