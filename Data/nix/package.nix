# Nix package for FEX (use via flake: nix build .#fex)
{
  pkgs ? import <nixpkgs> { },
  enableConfigUI ? true,
  enableLibraryForwarding ? true,
  gitRev ? "0000000000000000000000000000000000000000",
  # Source tree with submodules populated
  src ? null,
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
  inherit src;

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

  # Install a default Config.json pointing at the bundled RootFS so the
  # installed binaries work out of the box without further user setup.
  postInstall = ''
    mkdir -p $out/share/fex-emu
    cat > $out/share/fex-emu/Config.json <<EOF
    {
      "Config": {
        "RootFS": "${rootfs}",
        "ThunkHostLibs": "$out/lib/fex-emu/HostThunks",
        "ThunkGuestLibs": "$out/share/fex-emu/GuestThunks"
      }
    }
    EOF
  '';

  # wrapQtAppsHook otherwise wraps every executable in $out/bin; we only want FEXConfig wrapped.
  dontWrapQtApps = true;

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
    + pkgs.lib.optionalString enableLibraryForwarding ''
      # Add RPATH to host-side wrappers so dlopen works at runtime
      for libsdir in $out/lib/fex-emu/HostThunks; do
        patchelf --add-rpath "${pkgs.alsa-lib}/lib"      "$libsdir/libasound-host.so"
        patchelf --add-rpath "${pkgs.libdrm}/lib"        "$libsdir/libdrm-host.so"
        patchelf --add-rpath "${pkgs.vulkan-loader}/lib" "$libsdir/libvulkan-host.so"
      done
      for libsdir in $out/lib/fex-emu/HostThunks $out/lib/fex-emu/HostThunks_32; do
        patchelf --add-rpath "${pkgs.libglvnd}/lib"      "$libsdir/libEGL-host.so"
        patchelf --add-rpath "${pkgs.libglvnd}/lib"      "$libsdir/libGL-host.so"
        patchelf --add-rpath "${pkgs.wayland}/lib"       "$libsdir/libwayland-client-host.so"
      done
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
