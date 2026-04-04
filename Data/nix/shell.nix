# Shell for local development (use via flake: nix develop)
{
  pkgs ? import <nixpkgs> { },
  enableConfigUI ? true,
  enableLibraryForwarding ? true,
  linkerPackage ? pkgs.mold,
}:

let
  libForwardingShell = import ./LibraryForwarding/shell.nix { inherit pkgs; };
  fexPkg = import ./package.nix { inherit pkgs enableConfigUI enableLibraryForwarding; };
in
pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
  inputsFrom = [ fexPkg ] ++ pkgs.lib.optionals enableLibraryForwarding [ libForwardingShell ];
  inherit (libForwardingShell) FEX_CMAKE_TOOLCHAINS ROOTFS;

  packages = with pkgs; [
    # Build tools
    ccache
    linkerPackage

    # RootFS handling
    erofs-utils
    squashfsTools # unsquashfs, no squashfuse
    squashfuse # TODO: Not verified

    # Avoids spammy warning messages on non-default locales
    glibcLocales
  ];

  # TODO: vulkan-tools-lunarg, enable via VK_INSTANCE_LAYERS=VK_LAYER_LUNARG_api_dump (and maybe VK_LAYER_PATH=${vulkan-tools-lunarg}/share/vulkan/explicit_layer.d)

  env = fexPkg.passthru.env // {
    # Packages like mold must be unwrapped to get the required linker name
    LDFLAGS = "-fuse-ld=${linkerPackage.NIX_MAIN_PROGRAM or linkerPackage.pname}";

    # Set Qt runtime paths that wrapQtAppsHook would normally handle
    QT_PLUGIN_PATH = with pkgs;
      lib.optionalString enableConfigUI (
        lib.makeSearchPath "lib/qt-6/plugins" [
          qt6.qtbase
          qt6.qtwayland
        ]
      );
    QML2_IMPORT_PATH = with pkgs;
      lib.optionalString enableConfigUI (
        lib.makeSearchPath "lib/qt-6/qml" [
          qt6.qtbase
          qt6.qtdeclarative
        ]
      );

    # Use portable mode to ignore binfmt handlers
    FEX_PORTABLE = 1;
    FEX_ROOTFS = "${fexPkg.passthru.rootfs}";

    LD_LIBRARY_PATH = with pkgs;
      lib.optionalString enableLibraryForwarding (lib.makeLibraryPath [ vulkan-loader ]);

    CMAKE_GENERATOR = "Ninja";
  };

  shellHook = ''
    echo "RootFS: ${fexPkg.passthru.rootfs}"
    echo "Configure CMake for FEX build: cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \$FEX_CMAKE_TOOLCHAINS -DBUILD_THUNKS=ON"
  '';

  meta.description = "Shell for local FEX development";
}
