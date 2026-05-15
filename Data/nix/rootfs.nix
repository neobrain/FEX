{
  pkgs ? import <nixpkgs> { },
}:

# Fetch RootFS from FEX CDN.
# If this link becomes stale, look up the current one from https://rootfs.fex-emu.gg/RootFS_links.json
pkgs.stdenvNoCC.mkDerivation {
  name = "fex-rootfs-ubuntu-24.04";
  src = pkgs.fetchurl {
    url = "https://rootfs.fex-emu.gg/Ubuntu_24_04/2025-12-27/Ubuntu_24_04.sqsh";
    hash = "sha256-Eu1B/RPqTrLGXJOekgu2mUcCxErjO2i8f8h4FGi2mwQ=";
    # Fedora doesn't ship pygobject, which is required for steam-runtime-launch-options
    # url = "https://rootfs.fex-emu.gg/Fedora_43/2026-01-20/Fedora_43.sqsh";
    # hash = "sha256-OtSRkQLn2F8LFKbyzSD171JKvwacfVNrgxw7z/E/vyk=";
  };
  nativeBuildInputs = [ pkgs.squashfsTools ];
  dontUnpack = true;
  dontFixup = true;
  installPhase = ''
    unsquashfs -dest $out $src
  '';
}
