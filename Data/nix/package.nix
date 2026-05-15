# Nix package for FEX (use via flake: nix build .#fex)
{
  pkgs ? import <nixpkgs> { },
  enableConfigUI ? true,
  gitRev ? "0000000000000000000000000000000000000000",
  # Source tree with submodules populated
  src,
}:

let
  rootfs = import ./rootfs.nix { inherit pkgs; };
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
    ];

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    "-DBUILD_FEXCONFIG=${if enableConfigUI then "ON" else "OFF"}"
    "-DOVERRIDE_HASH=${gitRev}"
    "-DOVERRIDE_VERSION=FEX-local"
  ];

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
  };

  meta.description = "Emulator executables for Linux applications";
}
